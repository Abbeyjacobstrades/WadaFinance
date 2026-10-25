-- Run this in Supabase: SQL Editor > New query > paste > Run. Safe to run again.

-- 1) Public signals (free signals, history, indicators, broker)
create table if not exists signals (
  id text primary key,
  data jsonb not null,
  updated_at timestamptz default now()
);
alter table signals enable row level security;
drop policy if exists "anyone can read" on signals;
drop policy if exists "admin can insert" on signals;
drop policy if exists "admin can update" on signals;
create policy "anyone can read" on signals for select using (true);
create policy "admin can insert" on signals for insert to authenticated with check (true);
create policy "admin can update" on signals for update to authenticated using (true) with check (true);

-- 2) VIP: codes and VIP signals. Visitors can NOT read these tables directly.
create table if not exists vip_codes (
  slot int primary key check (slot between 1 and 30),
  code text unique not null,
  label text,
  created_at timestamptz default now()
);
alter table vip_codes add column if not exists expires_at timestamptz;
create table if not exists vip_data (
  id text primary key,
  data jsonb not null,
  updated_at timestamptz default now()
);
create table if not exists vip_attempts (ip text, at timestamptz default now());
alter table vip_codes enable row level security;
alter table vip_data enable row level security;
alter table vip_attempts enable row level security;
drop policy if exists "admin manages vip codes" on vip_codes;
drop policy if exists "admin manages vip data" on vip_data;
create policy "admin manages vip codes" on vip_codes for all to authenticated using (true) with check (true);
create policy "admin manages vip data" on vip_data for all to authenticated using (true) with check (true);

-- 3) The only way a visitor can read VIP signals: send a valid VIP code.
-- Wrong codes are rate limited (8 per 10 minutes per IP address).
create or replace function vip_get(p_code text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_ip text := split_part(coalesce(current_setting('request.headers', true)::json->>'x-forwarded-for', 'unknown'), ',', 1);
  v_data jsonb; v_found boolean; v_exp timestamptz;
begin
  delete from vip_attempts where at < now() - interval '1 hour';
  if (select count(*) from vip_attempts where ip = v_ip and at > now() - interval '10 minutes') >= 8 then
    return jsonb_build_object('ok', false, 'error', 'too_many');
  end if;
  select true, expires_at into v_found, v_exp from vip_codes where code = p_code;
  if not coalesce(v_found, false) then
    insert into vip_attempts(ip) values (v_ip);
    return jsonb_build_object('ok', false, 'error', 'invalid');
  end if;
  if v_exp is not null and v_exp <= now() then
    return jsonb_build_object('ok', false, 'error', 'expired');
  end if;
  select data into v_data from vip_data where id = 'main';
  return jsonb_build_object('ok', true, 'data', coalesce(v_data, '{}'::jsonb));
end $$;
revoke all on function vip_get(text) from public;
grant execute on function vip_get(text) to anon, authenticated;
