create index
  index_users_on_account_name_and_del_flg
on users (
  account_name,
  del_flg
);

create index
  index_users_on_authority_and_del_flg_and_created_at
on users (
  authority,
  del_flg,
  created_at
);

create index
  index_comments_on_post_id_and_created_at
on comments (
  post_id,
  created_at
);

create index
  index_posts_on_created_at
on posts (
  created_at
);

create index
  index_posts_on_user_id_and_created_at
on posts (
  user_id,
  created_at
);
