#ifndef TEMPORARY_TABLES_H
#define TEMPORARY_TABLES_H
/*
  Copyright (c) 2016 MariaDB Corporation

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
*/

#define TMP_TABLE_KEY_EXTRA 8

class Temporary_tables {
public:
  Temporary_tables() : m_thd(0), m_table_shares(0), m_opened_tables(0) {}
  bool init(THD *thd);
  bool is_empty();
  bool reset();
  bool cleanup();
  TABLE_SHARE *create_table(handlerton *hton, LEX_CUSTRING *frm,
                            const char *path, const char *db,
                            const char *table_name);
  TABLE_SHARE *find_table(const TABLE_LIST *tl);
  TABLE_SHARE *find_table_reduced_key_length(const char *key, uint key_length);
  TABLE_SHARE *find_table(const char *db, const char *table_name);
  TABLE *find_open_table(const char *db, const char *table_name);
  TABLE *create_and_use_table(handlerton *hton, LEX_CUSTRING *frm,
                              const char *path, const char *db,
                              const char *table_name, bool open_in_engine);
  TABLE *open_table(TABLE_SHARE *share, const char *alias, bool open_in_engine);
  bool open_table(TABLE_LIST *tl);
  bool open_tables(TABLE_LIST *tl);
  bool close_tables(bool all);
  bool rename_table(TABLE *table, const char *db, const char *table_name);
  bool drop_table(TABLE *table, bool *is_trans, bool delete_in_engine);
  void mark_tables_as_free_for_reuse();

private:
  uint create_table_def_key(char *key,
                            const char *db,
                            const char *table_name);
  TABLE_SHARE *find_table(const char *key, uint key_length);
  TABLE *find_open_table(const char *key, uint key_length);
  TABLE *open_table(const char *db, const char *table_name);
  bool close_table(TABLE *table);
  bool rm_temporary_table(handlerton *hton, const char *path);
  bool wait_for_prior_commit();
  bool write_query_log_events();
  void lock_tables();
  void unlock_tables();

  /*
    Return true if the table was created explicitly.
  */
  bool is_user_table(TABLE_SHARE *share)
  {
    const char *name= share->table_name.str;
    return strncmp(name, tmp_file_prefix, tmp_file_prefix_length);
  }

  /* List operations */
  template <class T>
  void link(T **list, T *element)
  {
    element->next= *list;
    if (element->next)
      element->next->prev= element;
    *list= element;
    (*list)->prev= 0;
  }

  template <class T>
  void unlink(T **list, T *element)
  {
    if (element->prev)
    {
      element->prev->next= element->next;
      if (element->prev->next)
        element->next->prev= element->prev;
    }
    else
    {
      DBUG_ASSERT(element == *list);

      *list= element->next;
      if (*list)
        element->next->prev= 0;
    }
  }

  uint tmpkeyval(TABLE_SHARE *share)
  {
    return uint4korr(share->table_cache_key.str +
                     share->table_cache_key.length - 4);
  }

private:
  THD *m_thd;
  TABLE_SHARE *m_table_shares;
  TABLE *m_opened_tables;
};

#endif /* TEMPORARY_TABLES_H */
