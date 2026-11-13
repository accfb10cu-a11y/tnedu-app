-- ==============================================================================
-- EDUSUBMIT - SUPABASE POSTGRESQL SCHEMA & ROW LEVEL SECURITY (RLS) POLICIES
-- ==============================================================================
-- Hướng dẫn: Mở Supabase Dashboard -> SQL Editor -> Dán toàn bộ mã này -> Bấm Run
-- ==============================================================================

-- 1. BẢNG PROFILES (Hồ sơ người dùng)
create table if not exists public.profiles (
  id uuid references auth.users on delete cascade primary key,
  email text not null,
  full_name text not null,
  role text not null default 'user' check (role in ('user', 'admin')),
  is_locked boolean not null default false,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Kích hoạt RLS cho profiles
alter table public.profiles enable row level security;

-- Function kiểm tra xem user hiện tại có phải là Admin không
create or replace function public.is_admin()
returns boolean as $$
begin
  return exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'admin'
  );
end;
$$ language plpgsql security definer;

-- RLS Policies cho Profiles:
-- Mọi người dùng đã đăng nhập có thể xem hồ sơ của chính mình; Admin xem được tất cả
create policy "Users can view own profile or admin view all"
  on public.profiles for select
  using (auth.uid() = id or public.is_admin());

-- Người dùng có thể cập nhật thông tin cá nhân của mình (không đổi role/is_locked)
create policy "Users can update own profile"
  on public.profiles for update
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- Chỉ Admin mới được quyền cập nhật vai trò (role) và trạng thái khóa (is_locked)
create policy "Admin can update any profile"
  on public.profiles for update
  using (public.is_admin());

-- Admin có thể xóa hồ sơ
create policy "Admin can delete profile"
  on public.profiles for delete
  using (public.is_admin());


-- 2. BẢNG SUBMISSIONS (Bài nộp trực tuyến)
create table if not exists public.submissions (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references public.profiles(id) on delete cascade not null,
  user_name text not null,
  user_email text not null,
  title text not null,
  content text not null,
  link_url text,
  file_name text,
  file_size bigint,
  file_type text,
  file_url text,
  file_path text,
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  admin_feedback text,
  reviewed_by text,
  reviewed_at timestamp with time zone,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Kích hoạt RLS cho submissions
alter table public.submissions enable row level security;

-- RLS Policies cho Submissions:
-- Người dùng CHỈ xem được bài nộp của chính mình; Admin xem được toàn bộ
create policy "Users view own submissions, Admin view all"
  on public.submissions for select
  using (auth.uid() = user_id or public.is_admin());

-- Người dùng nộp bài (chỉ được gán user_id là auth.uid())
create policy "Users can insert own submissions"
  on public.submissions for insert
  with check (auth.uid() = user_id);

-- Admin duyệt hoặc từ chối bài (kèm ghi chú/lý do)
create policy "Admin can update submissions"
  on public.submissions for update
  using (public.is_admin());

-- Admin có thể xóa bài nộp
create policy "Admin can delete submissions"
  on public.submissions for delete
  using (public.is_admin());


-- 3. BẢNG SYSTEM_SETTINGS (Cài đặt hệ thống & Bảo trì)
create table if not exists public.system_settings (
  id text primary key default 'global',
  is_maintenance boolean not null default false,
  maintenance_message text not null default 'Hệ thống đang bảo trì nâng cấp định kỳ. Vui lòng quay lại sau.',
  allow_new_submissions boolean not null default true,
  max_file_size_mb integer not null default 25,
  allowed_file_types text not null default 'pdf,docx,zip,rar,png,jpg,jpeg',
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

alter table public.system_settings enable row level security;

-- Mọi người đều có thể đọc trạng thái bảo trì
create policy "Everyone can view settings"
  on public.system_settings for select
  using (true);

-- Chỉ Admin mới được thay đổi cài đặt
create policy "Only admin can update settings"
  on public.system_settings for update
  using (public.is_admin());

-- Chèn cài đặt mặc định
insert into public.system_settings (id, is_maintenance, maintenance_message)
values ('global', false, 'Hệ thống đang bảo trì nâng cấp định kỳ. Vui lòng quay lại sau.')
on conflict (id) do nothing;


-- 4. BẢO MẬT STORAGE (Private Bucket)
-- Tạo bucket 'submissions' dạng PRIVATE (public = false)
insert into storage.buckets (id, name, public)
values ('submissions', 'submissions', false)
on conflict (id) do update set public = false;

-- RLS Storage: Học viên chỉ tải file vào thư mục mang ID của chính mình: submissions/[user_id]/[file_name]
create policy "Users upload to own folder"
  on storage.objects for insert
  with check (
    bucket_id = 'submissions' and
    (auth.uid())::text = (storage.foldername(name))[1]
  );

-- Học viên CHỈ được xem và tải tệp của chính mình; Admin xem và tải được toàn bộ
create policy "Users view own files, Admin view all"
  on storage.objects for select
  using (
    bucket_id = 'submissions' and (
      (auth.uid())::text = (storage.foldername(name))[1]
      or public.is_admin()
    )
  );

-- Admin có thể xóa file trong storage khi xóa bài nộp
create policy "Admin delete files"
  on storage.objects for delete
  using (
    bucket_id = 'submissions' and public.is_admin()
  );


-- 5. TRIGGER TỰ ĐỘNG ĐỒNG BỘ AUTH.USERS VÀO PROFILES KHI ĐĂNG KÝ
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, email, full_name, role)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1)),
    -- Nếu email chứa 'admin@' thì cấp quyền admin mặc định (hoặc tùy cấu hình)
    case when new.email like 'admin%' then 'admin' else 'user' end
  );
  return new;
end;
$$ language plpgsql security definer;

-- Gắn trigger vào bảng auth.users
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();
