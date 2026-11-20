-- Outlift: fix friend-request hole, simplify and speed up security rules.

-- 1. Friend requests: the receiver may only change the status to 'accepted'.
--    Before, they could rewrite who sent the request and gain access to anyone's data.
create or replace function public.friends_lock_people()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.requester <> old.requester or new.addressee <> old.addressee then
    raise exception 'Cannot change who is in a friend request';
  end if;
  return new;
end;
$$;

drop trigger if exists friends_lock_people on public.friends;
create trigger friends_lock_people
  before update on public.friends
  for each row execute function public.friends_lock_people();

-- 2. Index for looking up requests by receiver.
create index if not exists friends_addressee_idx on public.friends (addressee);

-- 3. Basic sanity checks on logged sets.
alter table public.entries
  add constraint entries_w_nonneg check (w >= 0),
  add constraint entries_r_nonneg check (r >= 0),
  add constraint entries_wk_positive check (wk >= 1);

-- 4. Rewrite security rules: signed-in users only, look up the user once per query,
--    and merge the two read rules on entries into one.

-- entries
drop policy if exists "own select" on public.entries;
drop policy if exists "friends read entries" on public.entries;
drop policy if exists "own insert" on public.entries;
drop policy if exists "own update" on public.entries;
drop policy if exists "own delete" on public.entries;

create policy "entries select" on public.entries for select to authenticated
  using (
    user_id = (select auth.uid())
    or exists (
      select 1 from public.friends f
      where f.status = 'accepted'
        and ((f.requester = (select auth.uid()) and f.addressee = entries.user_id)
          or (f.addressee = (select auth.uid()) and f.requester = entries.user_id))
    )
  );
create policy "entries insert" on public.entries for insert to authenticated
  with check (user_id = (select auth.uid()));
create policy "entries update" on public.entries for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));
create policy "entries delete" on public.entries for delete to authenticated
  using (user_id = (select auth.uid()));

-- friends
drop policy if exists "friends select" on public.friends;
drop policy if exists "friends insert" on public.friends;
drop policy if exists "friends accept" on public.friends;
drop policy if exists "friends delete" on public.friends;

create policy "friends select" on public.friends for select to authenticated
  using ((select auth.uid()) in (requester, addressee));
create policy "friends insert" on public.friends for insert to authenticated
  with check (requester = (select auth.uid()) and status = 'pending');
create policy "friends accept" on public.friends for update to authenticated
  using (addressee = (select auth.uid()))
  with check (addressee = (select auth.uid()) and status = 'accepted');
create policy "friends delete" on public.friends for delete to authenticated
  using ((select auth.uid()) in (requester, addressee));

-- profiles
drop policy if exists "profiles select" on public.profiles;
drop policy if exists "profiles insert" on public.profiles;
drop policy if exists "profiles update" on public.profiles;

create policy "profiles select" on public.profiles for select to authenticated
  using (
    id = (select auth.uid())
    or exists (
      select 1 from public.friends f
      where (f.requester = (select auth.uid()) and f.addressee = profiles.id)
         or (f.addressee = (select auth.uid()) and f.requester = profiles.id)
    )
  );
create policy "profiles insert" on public.profiles for insert to authenticated
  with check (id = (select auth.uid()));
create policy "profiles update" on public.profiles for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));
