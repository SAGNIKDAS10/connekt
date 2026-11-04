-- Connekt backend schema (Supabase / PostgreSQL)
-- Run this in Supabase Dashboard > SQL Editor.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default 'Listener',
  friend_code text unique not null default upper(substr(encode(gen_random_bytes(5), 'hex'), 1, 6)),
  created_at timestamptz not null default now()
);

create table if not exists public.rooms (
  id uuid primary key default gen_random_uuid(),
  code text unique not null default upper(substr(encode(gen_random_bytes(5), 'hex'), 1, 6)),
  name text not null default 'Listening room',
  host_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.room_members (
  room_id uuid not null references public.rooms(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (room_id, user_id)
);

create table if not exists public.tracks (
  id uuid primary key default gen_random_uuid(),
  room_id uuid not null references public.rooms(id) on delete cascade,
  added_by uuid not null references public.profiles(id) on delete cascade,
  url text not null,
  provider text not null check (provider in ('YouTube','SoundCloud','Spotify')),
  title text not null default 'Shared track',
  position bigint generated always as identity,
  created_at timestamptz not null default now()
);

create table if not exists public.room_playback (
  room_id uuid primary key references public.rooms(id) on delete cascade,
  current_track_id uuid references public.tracks(id) on delete set null,
  is_playing boolean not null default false,
  updated_by uuid references public.profiles(id) on delete set null,
  updated_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
alter table public.rooms enable row level security;
alter table public.room_members enable row level security;
alter table public.tracks enable row level security;
alter table public.room_playback enable row level security;

-- Profiles: signed-in users can read profiles and edit only their own.
drop policy if exists "profiles readable by authenticated" on public.profiles;
create policy "profiles readable by authenticated" on public.profiles for select to authenticated using (true);
drop policy if exists "users insert own profile" on public.profiles;
create policy "users insert own profile" on public.profiles for insert to authenticated with check (auth.uid() = id);
drop policy if exists "users update own profile" on public.profiles;
create policy "users update own profile" on public.profiles for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);

-- A room is visible to its members; the host creates it.
drop policy if exists "members can view rooms" on public.rooms;
create policy "members can view rooms" on public.rooms for select to authenticated using (
  exists (select 1 from public.room_members m where m.room_id = id and m.user_id = auth.uid())
  or host_id = auth.uid()
);
drop policy if exists "signed in users create rooms" on public.rooms;
create policy "signed in users create rooms" on public.rooms for insert to authenticated with check (host_id = auth.uid());
drop policy if exists "host updates room" on public.rooms;
create policy "host updates room" on public.rooms for update to authenticated using (host_id = auth.uid()) with check (host_id = auth.uid());
drop policy if exists "host deletes room" on public.rooms;
create policy "host deletes room" on public.rooms for delete to authenticated using (host_id = auth.uid());

-- Room code lookup and membership: signed-in users may join a room by code.
drop policy if exists "members can see room members" on public.room_members;
create policy "members can see room members" on public.room_members for select to authenticated using (
  user_id = auth.uid() or exists (select 1 from public.room_members mine where mine.room_id = room_id and mine.user_id = auth.uid())
);
drop policy if exists "users join rooms" on public.room_members;
create policy "users join rooms" on public.room_members for insert to authenticated with check (user_id = auth.uid());
drop policy if exists "users leave rooms" on public.room_members;
create policy "users leave rooms" on public.room_members for delete to authenticated using (user_id = auth.uid());

-- Members can read and add queue tracks; users can remove their own tracks.
drop policy if exists "room members read tracks" on public.tracks;
create policy "room members read tracks" on public.tracks for select to authenticated using (
  exists (select 1 from public.room_members m where m.room_id = tracks.room_id and m.user_id = auth.uid())
);
drop policy if exists "room members add tracks" on public.tracks;
create policy "room members add tracks" on public.tracks for insert to authenticated with check (
  added_by = auth.uid() and exists (select 1 from public.room_members m where m.room_id = tracks.room_id and m.user_id = auth.uid())
);
drop policy if exists "users remove own tracks" on public.tracks;
create policy "users remove own tracks" on public.tracks for delete to authenticated using (
  added_by = auth.uid() and exists (select 1 from public.room_members m where m.room_id = tracks.room_id and m.user_id = auth.uid())
);

-- Members can read/update shared playback state.
drop policy if exists "room members read playback" on public.room_playback;
create policy "room members read playback" on public.room_playback for select to authenticated using (
  exists (select 1 from public.room_members m where m.room_id = room_playback.room_id and m.user_id = auth.uid())
);
drop policy if exists "room members write playback" on public.room_playback;
create policy "room members write playback" on public.room_playback for all to authenticated using (
  exists (select 1 from public.room_members m where m.room_id = room_playback.room_id and m.user_id = auth.uid())
) with check (
  exists (select 1 from public.room_members m where m.room_id = room_playback.room_id and m.user_id = auth.uid())
);

-- Create a profile automatically after email signup.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles (id, display_name)
  values (new.id, coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email, '@', 1)));
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- Enable realtime for collaborative queue and playback updates.
do $$
begin
  alter publication supabase_realtime add table public.tracks;
exception when duplicate_object then null;
end $$;
do $$
begin
  alter publication supabase_realtime add table public.room_playback;
exception when duplicate_object then null;
end $$;
