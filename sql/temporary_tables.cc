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

#include "sql_acl.h"                            /* TMP_TABLE_ACLS */
#include "sql_base.h"                           /* free_io_cache,
                                                   get_table_def_key,
                                                   tdc_create_key */
#include "lock.h"                               /* mysql_lock_remove */
#include "log_event.h"                          /* Query_log_event */
#include "sql_show.h"                           /* append_identifier */
#include "sql_handler.h"                        /* mysql_ha_rm_temporary_tables */
#include "temporary_tables.h"                   /* Temporary_tables */
#include "rpl_rli.h"                            /* rpl_group_info */


/*
  Initialize the Temporary_tables object. Currently it always returns
  false (success).

  @param thd [IN]                     Thread handle

  @return false                       Success
          true                        Error
*/
bool Temporary_tables::init(THD *thd)
{
  DBUG_ENTER("Temporary_tables::init");
  this->m_thd= thd;
  DBUG_RETURN(false);
}


/*
  Check whether temporary tables exist. The decision is made based on the
  existence of TABLE_SHAREs.

  @return false                       Temporary tables exist
          true                        No temporary table exist
*/
bool Temporary_tables::is_empty()
{
  bool result;

  if (!m_thd)
  {
    return true;
  }

  rpl_group_info *rgi_slave= m_thd->rgi_slave;

  if (rgi_slave)
  {
    result= (rgi_slave->rli->save_temp_table_shares == NULL) ? true : false;
  }
  else
  {
    result= (m_table_shares == NULL) ? true : false;
  }

  return result;
}


/*
  Reset the Temporary_tables object. Currently, it always returns
  false (success).

  @return false                       Success
          true                        Error
*/
bool Temporary_tables::reset()
{
  DBUG_ENTER("Temporary_tables::reset");
  m_table_shares= 0;
  m_opened_tables= 0;
  DBUG_RETURN(false);
}


/*
  Cleanup the session's temporary tables by closing all open temporary tables
  as well as freeing the respective TABLE_SHAREs.
  It also writes "DROP TEMPORARY TABLE .." query log events to the binary log.

  Currently, it always returns false (success).

  @return false                       Success
          true                        Error
*/
bool Temporary_tables::cleanup()
{
  DBUG_ENTER("Temporary_tables::cleanup");

  TABLE_SHARE *share;
  TABLE_SHARE *next;

  lock_tables();

  /*
    Ensure we don't have open HANDLERs for tables we are about to close.
    This is necessary when close_temporary_tables() is called as part
    of execution of BINLOG statement (e.g. for format description event).
  */
  mysql_ha_rm_temporary_tables(m_thd);

  // Close all open temporary tables.
  close_tables(true);

  // Write DROP TEMPORARY TABLE query log events to binary log.
  if (!m_thd->rgi_slave)
  {
    write_query_log_events();
  }

  // Free all TABLE_SHARES.
  share= m_table_shares;

  while (share) {
    next= share->next;
    rm_temporary_table(share->db_type(), share->path.str);

    /* Delete the share from table share list */
    unlink<TABLE_SHARE>(&m_table_shares, share);

    free_table_share(share);
    my_free(share);

    /* Decrement Slave_open_temp_table_definitions status variable count. */
    if (m_thd->rgi_slave)
    {
      thread_safe_decrement32(&slave_open_temp_table_definitions);
    }

    share= next;
  }

  reset();

  unlock_tables();

  DBUG_RETURN(false);
}


/*
  Create a temporary table.

  @param hton [in]                    Handlerton
  @param frm  [in]                    Binary frm image
  @param path [in]                    File path (without extension)
  @param db   [in]                    Schema name
  @param table_name [in]              Table name

  @return Success                     A pointer to table share object
          Failure                     NULL
*/
TABLE_SHARE *Temporary_tables::create_table(handlerton *hton, LEX_CUSTRING *frm,
                                           const char *path, const char *db,
                                           const char *table_name)
{
  DBUG_ENTER("Temporary_tables::create_table");

  TABLE_SHARE *share= NULL;
  char key_cache[MAX_DBKEY_LENGTH], *saved_key_cache, *tmp_path;
  uint key_length;
  int res;

  lock_tables();

  if (wait_for_prior_commit())
  {
    goto end;                                   /* Failure */
  }

  /* Create the table definition key for the temporary table. */
  key_length= create_table_def_key(key_cache, db, table_name);

  if (!(share= (TABLE_SHARE *) my_malloc(sizeof(TABLE_SHARE) + strlen(path) +
                                         1 + key_length, MYF(MY_WME))))
  {
    goto end;                                   /* Out of memory */
  }

  tmp_path= (char *)(share + 1);
  saved_key_cache= strmov(tmp_path, path) + 1;
  memcpy(saved_key_cache, key_cache, key_length);

  init_tmp_table_share(m_thd, share, saved_key_cache, key_length,
                       strend(saved_key_cache) + 1, tmp_path);

  share->db_plugin= ha_lock_engine(m_thd, hton);

  /*
    Prefer using frm image over file. The image might not be available in
    ALTER TABLE, when the discovering engine took over the ownership (see
    TABLE::read_frm_image).
  */
  res= (frm->str)
    ? share->init_from_binary_frm_image(m_thd, false, frm->str, frm->length)
    : open_table_def(m_thd, share, GTS_TABLE | GTS_USE_DISCOVERY);

  if (res)
  {
    /*
      No need to lock share->mutex as this is not needed for temporary tables.
    */
    free_table_share(share);
    my_free(share);
    share= NULL;
    goto end;
  }

  share->m_psi= PSI_CALL_get_table_share(true, share);

  /* Add share to the head of table share list. */
  link<TABLE_SHARE>(&m_table_shares, share);

  /* Increment Slave_open_temp_table_definitions status variable count. */
  if (m_thd->rgi_slave)
  {
    thread_safe_increment32(&slave_open_temp_table_definitions);
  }

end:
  unlock_tables();

  DBUG_RETURN(share);
}


/*
  Lookup the TABLE_SHARE using the given db/table_name.The server_id and
  pseudo_thread_id used to generate table definition key is taken from
  m_thd (see create_table_def_key()). Return NULL is none found.

  @return Success                     A pointer to table share object
          Failure                     NULL
*/
TABLE_SHARE *Temporary_tables::find_table(const char *db,
                                          const char *table_name)
{
  DBUG_ENTER("Temporary_tables::find_table");

  TABLE_SHARE *share;
  char key[MAX_DBKEY_LENGTH];
  uint key_length;

  key_length= create_table_def_key(key, db, table_name);
  share= find_table(key, key_length);

  DBUG_RETURN(share);
}


/*
  Lookup TABLE_SHARE using the specified TABLE_LIST element. Return NULL is none
  found.

  @return Success                     A pointer to table share object
          Failure                     NULL
*/
TABLE_SHARE *Temporary_tables::find_table(const TABLE_LIST *tl)
{
  DBUG_ENTER("Temporary_tables::find_table");

  TABLE_SHARE *share;
  const char *tmp_key;
  char key[MAX_DBKEY_LENGTH];
  uint key_length;

  key_length= get_table_def_key(tl, &tmp_key);
  memcpy(key, tmp_key, key_length);
  int4store(key + key_length, m_thd->variables.server_id);
  int4store(key + key_length + 4, m_thd->variables.pseudo_thread_id);
  key_length += TMP_TABLE_KEY_EXTRA;

  share= find_table(key, key_length);

  DBUG_RETURN(share);
}


/*
  Lookup TABLE_SHARE using the specified table definition key. Return NULL is
  none found.

  @return Success                     A pointer to table share object
          Failure                     NULL
*/
TABLE_SHARE *Temporary_tables::find_table(const char *key,
                                          uint key_length)
{
  DBUG_ENTER("Temporary_tables::find_table");

  TABLE_SHARE *share;
  TABLE_SHARE *result= NULL;

  lock_tables();

  for (share= m_table_shares; share; share= share->next)
  {
    if (share->table_cache_key.length == key_length &&
        !(memcmp(share->table_cache_key.str, key, key_length)))
    {
      result= share;
      break;
    }
  }

  unlock_tables();

  DBUG_RETURN(result);
}


/*
  Lookup TABLE_SHARE based on the specified key. This key, however, is not
  the usual key used for temporary tables. It does not contain server_id &
  pseudo_thread_id. This function is essentially used use to check whether
  there is any temporary table which _shadows_ a base table.
  (see: Query_cache::send_result_to_client())

  @return Success                     A pointer to table share object
          Failure                     NULL
*/
TABLE_SHARE *Temporary_tables::find_table_reduced_key_length(const char *key,
                                                             uint key_length)
{
  DBUG_ENTER("Temporary_tables::find_table_reduced_key_length");

  TABLE_SHARE *share;
  TABLE_SHARE *result= NULL;

  lock_tables();

  for (share= m_table_shares; share; share= share->next)
  {
    if ((share->table_cache_key.length - TMP_TABLE_KEY_EXTRA) == key_length &&
        !(memcmp(share->table_cache_key.str, key, key_length)))
    {
      result= share;
      break;
    }
  }

  unlock_tables();

  DBUG_RETURN(result);
}


/*
  Lookup the list of opened temporary tables using the specified
  db/table_name. Return NULL is none found.

  @return Success                     A pointer to table object
          Failure                     NULL
*/
TABLE *Temporary_tables::find_open_table(const char *db,
                                         const char *table_name)
{
  DBUG_ENTER("Temporary_tables::find_open_table");

  TABLE *table;
  char key[MAX_DBKEY_LENGTH];
  uint key_length;

  if (wait_for_prior_commit())
  {
    DBUG_RETURN(NULL);                          /* Failure */
  }

  key_length= create_table_def_key(key, db, table_name);

  table= find_open_table(key, key_length);

  DBUG_RETURN(table);
}


/*
  Lookup the list of opened temporary tables using the specified
  key. Return NULL is none found.

  @return Success                     A pointer to table object
          Failure                     NULL
*/
TABLE *Temporary_tables::find_open_table(const char *key,
                                         uint key_length)
{
  DBUG_ENTER("Temporary_tables::find_open_table");

  TABLE *table, *result= NULL;

  for (table= m_opened_tables; table; table= table->next)
  {
    if (table->s->table_cache_key.length == key_length &&
        !(memcmp(table->s->table_cache_key.str, key, key_length)))
    {
      result= table;
      break;
    }
  }

  DBUG_RETURN(result);
}


/*
  Create a temporary table, open it and return the TABLE handle.

  @param hton [in]                    Handlerton
  @param frm  [in]                    Binary frm image
  @param path [in]                    File path (without extension)
  @param db   [in]                    Schema name
  @param table_name [in]              Table name
  @param open_in_engine [in]          Whether open table in SE


  @return Success                     A pointer to table object
          Failure                     NULL
*/
TABLE *Temporary_tables::create_and_use_table(handlerton *hton,
                                              LEX_CUSTRING *frm,
                                              const char *path,
                                              const char *db,
                                              const char *table_name,
                                              bool open_in_engine)
{
  DBUG_ENTER("Temporary_tables::create_and_use_table");

  TABLE_SHARE *share;
  TABLE *table;

  if (wait_for_prior_commit())
  {
    DBUG_RETURN(NULL);                          /* Failure */
  }

  if (!(share= create_table(hton, frm, path, db, table_name)))
  {
    DBUG_RETURN(NULL);
  }

  if ((table= open_table(share, table_name, open_in_engine)))
  {
     DBUG_RETURN(table);
  }

  DBUG_RETURN(NULL);
}


/*
  Open a table from the specified TABLE_SHARE with the given alias.

  @param share [in]                   Table share
  @param alias [in]                   Table alias
  @param open_in_engine [in]          Whether open table in SE

  @return Success                     A pointer to table object
          Failure                     NULL
*/
TABLE *Temporary_tables::open_table(TABLE_SHARE *share,
                                    const char *alias,
                                    bool open_in_engine)
{
  DBUG_ENTER("Temporary_tables::open_table");

  TABLE *table;

  if (wait_for_prior_commit())
  {
    DBUG_RETURN(NULL);                          /* Failure */
  }

  if (!(table= (TABLE *) my_malloc(sizeof(TABLE), MYF(MY_WME))))
  {
    DBUG_RETURN(NULL);                          /* Out of memory */
  }

  if (open_table_from_share(m_thd, share, alias,
                            (open_in_engine) ?
                            (uint) (HA_OPEN_KEYFILE | HA_OPEN_RNDFILE |
                                    HA_GET_INDEX) : 0,
                            (uint) (READ_KEYINFO | COMPUTE_TYPES |
                                    EXTRA_RECORD),
                            ha_open_options,
                            table,
                            open_in_engine ? false : true))
  {
    my_free(table);
    DBUG_RETURN(NULL);
  }

  table->reginfo.lock_type= TL_WRITE;           /* Simulate locked */
  table->grant.privilege= TMP_TABLE_ACLS;
  share->tmp_table= (table->file->has_transactions() ?
                     TRANSACTIONAL_TMP_TABLE : NON_TRANSACTIONAL_TMP_TABLE);

  table->pos_in_table_list= 0;
  table->query_id= m_thd->query_id;

  lock_tables();

  /* Add table to the head of table list. */
  link<TABLE>(&m_opened_tables, table);

  /* Increment Slave_open_temp_table_definitions status variable count. */
  if (m_thd->rgi_slave)
  {
    thread_safe_increment32(&slave_open_temp_tables);
  }

  unlock_tables();

  DBUG_PRINT("tmptable", ("Opened table: '%s'.'%s' 0x%lx", table->s->db.str,
                          table->s->table_name.str, (long) table));
  DBUG_RETURN(table);
}


/*
  Lookup the table share list and open a table based on db/table_name.
  Return NULL if none found.

  @param db [in]                      Schema name
  @param table_name [in]              Table name

  @return Success                     A pointer to table object
          Failure                     0
*/
TABLE *Temporary_tables::open_table(const char *db,
                                    const char *table_name)
{
  DBUG_ENTER("Temporary_tables::open_table");

  TABLE *result= 0;
  TABLE_SHARE *share;

  if ((share= find_table(db, table_name)))
  {
    result= open_table(share, table_name, true);
  }

  DBUG_RETURN(result);
}


/*
  Lookup the table share list and open a table based on the specified
  TABLE_LIST element. Return false if the table was opened successfully.

  @param tl [in]                      TABLE_LIST

  @return false                       Success
          true                        Failure
*/
bool Temporary_tables::open_table(TABLE_LIST *tl)
{
  DBUG_ENTER("Temporary_tables::open_table");

  TABLE *table= NULL;
  TABLE_SHARE *share;

  /*
    Code in open_table() assumes that TABLE_LIST::table can be non-zero only
    for pre-opened temporary tables.
  */
  DBUG_ASSERT(tl->table == NULL);

  /*
    This function should not be called for cases when derived or I_S
    tables can be met since table list elements for such tables can
    have invalid db or table name.
    Instead Temporary_tables::open_tables() should be used.
  */
  DBUG_ASSERT(!tl->derived && !tl->schema_table);

  if (wait_for_prior_commit())
  {
    DBUG_RETURN(true);                          /* Failure */
  }

  lock_tables();

  if (tl->open_type == OT_BASE_ONLY || m_table_shares == NULL)
  {
    DBUG_PRINT("info", ("skip_temporary is set or no temporary tables"));
    unlock_tables();
    DBUG_RETURN(false);
  }

  unlock_tables();

  if ((share= find_table(tl)) &&
      (table= open_table(share, tl->get_table_name(), true)))
  {
    if (wait_for_prior_commit())
    {
      DBUG_RETURN(true);                        /* Failure */
    }

#ifdef WITH_PARTITION_STORAGE_ENGINE
    if (tl->partition_names)
    {
      /* Partitioned temporary tables is not supported. */
      DBUG_ASSERT(!table->part_info);
      my_error(ER_PARTITION_CLAUSE_ON_NONPARTITIONED, MYF(0));
      DBUG_RETURN(true);
    }
#endif

    table->query_id= m_thd->query_id;
    m_thd->thread_specific_used= true;
    /* It is neither a derived table nor non-updatable view. */
    tl->updatable= true;
    tl->table= table;
    table->init(m_thd, tl);
    DBUG_RETURN(false);
  }

  if (!table &&
      tl->open_type == OT_TEMPORARY_ONLY &&
      tl->open_strategy == TABLE_LIST::OPEN_NORMAL)
  {
    my_error(ER_NO_SUCH_TABLE, MYF(0), tl->db, tl->table_name);
    DBUG_RETURN(true);
  }

  DBUG_RETURN(false);
}


/*
  Pre-open temporary tables corresponding to table list elements.

  @note One should finalize process of opening temporary tables
        by calling open_tables(). This function is responsible
        for table version checking and handling of merge tables.

  @param tl [in]                      TABLE_LIST

  @return false                       On success. If a temporary table exists
                                      for the given element, tl->table is set.
          true                        On error. my_error() has been called.
*/
bool Temporary_tables::open_tables(TABLE_LIST *tl)
{
  DBUG_ENTER("Temporary_tables::open_tables");

  TABLE_LIST *first_not_own;

  if (wait_for_prior_commit())
  {
    DBUG_RETURN(NULL);                          /* Failure */
  }

  first_not_own= m_thd->lex->first_not_own_table();

  for (TABLE_LIST *table= tl;
       table && table != first_not_own;
       table= table->next_global)
  {
    if (table->derived || table->schema_table)
    {
      /*
        Derived and I_S tables will be handled by a later call to open_tables().
      */
      continue;
    }

    if ((m_thd->temporary_tables.open_table(table)))
    {
      DBUG_RETURN(true);
    }
  }

  DBUG_RETURN(false);
}


/*
  Close a temporary table.

  @param table [in]                   Table handle

  @return false                       Success
          true                        Error
*/
bool Temporary_tables::close_table(TABLE *table)
{
  DBUG_ENTER("Temporary_tables::close_table");
  DBUG_PRINT("tmptable", ("closing table: '%s'.'%s' 0x%lx  alias: '%s'",
                          table->s->db.str, table->s->table_name.str,
                          (long) table, table->alias.c_ptr()));

  /* Delete the table from table list */
  unlink<TABLE>(&m_opened_tables, table);

  free_io_cache(table);
  closefrm(table, false);
  my_free(table);

  /* Decrement Slave_open_temp_table_definitions status variable count. */
  if (m_thd->rgi_slave)
  {
    thread_safe_decrement32(&slave_open_temp_tables);
  }

  DBUG_RETURN(false);
}

/*
  Close all the opened table. When 'all' is set to false, tables opened by
  handlers and ones with query_id different than that of m_thd will not be
  be closed. Currently, false (success) is always returned.

  @param all [in]                     Whether to close all tables?

  @return false                       Success
          true                        Failure
*/
bool Temporary_tables::close_tables(bool all)
{
  TABLE *table;
  TABLE *next;

  table= m_opened_tables;

  while(table) {
    next= table->next;

    if (all || ((table->query_id == m_thd->query_id) &&
                !(table->open_by_handler)))
    {
      mysql_lock_remove(m_thd, m_thd->lock, table);
      close_table(table);
    }

    table= next;
  }
  return false;
}


/*
  Write query log events with "DROP TEMPORARY TABLES .." for each pseudo
  thread to the binary log.

  @return false                       Success
          true                        Error
*/
bool Temporary_tables::write_query_log_events()
{
  DBUG_ENTER("Temporary_tables::write_query_log_events");
  DBUG_ASSERT(!m_thd->rgi_slave);

  TABLE_SHARE *share;
  TABLE_SHARE *next;
  TABLE_SHARE *prev_share;
  // Assume thd->variables.option_bits has OPTION_QUOTE_SHOW_CREATE.
  bool was_quote_show= true;
  bool error= 0;
  bool found_user_tables= false;
  // Better add "IF EXISTS" in case a RESET MASTER has been done.
  const char stub[]= "DROP /*!40005 TEMPORARY */ TABLE IF EXISTS ";
  char buf[FN_REFLEN];

  /*
    Return in case there are no temporary tables or binary logging is
    disabled.
  */
  if (!(m_table_shares && mysql_bin_log.is_open()))
  {
    DBUG_RETURN(false);
  }

  String s_query(buf, sizeof(buf), system_charset_info);
  s_query.copy(stub, sizeof(stub) - 1, system_charset_info);

  /*
    Insertion sort of temporary tables by pseudo_thread_id to build ordered
    list of sublists of equal pseudo_thread_id.
  */

  for (prev_share= m_table_shares, share= prev_share->next;
       share;
       prev_share= share, share= share->next)
  {
    TABLE_SHARE *prev_sorted;                   /* Same as for prev_share */
    TABLE_SHARE *sorted;

    if (is_user_table(share))
    {
      if (!found_user_tables)
        found_user_tables= true;

      for (prev_sorted= NULL, sorted= m_table_shares;
           sorted != share;
           prev_sorted= sorted, sorted= sorted->next)
      {
        if (!is_user_table(sorted) ||
            tmpkeyval(sorted) > tmpkeyval(share))
        {
          /*
            Move into the sorted part of the list from the unsorted.
          */
          prev_share->next= share->next;
          share->next= sorted;
          if (prev_sorted)
          {
            prev_sorted->next= share;
          }
          else
          {
            m_table_shares= share;
          }
          share= prev_share;
          break;
        }
      }
    }
  }

  /*
    We always quote db, table names though it is slight overkill.
  */
  if (found_user_tables &&
      !(was_quote_show= MY_TEST(m_thd->variables.option_bits &
                                OPTION_QUOTE_SHOW_CREATE)))
  {
    m_thd->variables.option_bits |= OPTION_QUOTE_SHOW_CREATE;
  }

  /*
    Scan sorted temporary tables to generate sequence of DROP.
  */
  for (share= m_table_shares; share; share= next)
  {
    if (is_user_table(share))
    {
      bool save_thread_specific_used= m_thd->thread_specific_used;
      my_thread_id save_pseudo_thread_id= m_thd->variables.pseudo_thread_id;
      char db_buf[FN_REFLEN];
      String db(db_buf, sizeof(db_buf), system_charset_info);

      /*
        Set pseudo_thread_id to be that of the processed table.
      */
      m_thd->variables.pseudo_thread_id= tmpkeyval(share);

      db.copy(share->db.str, share->db.length, system_charset_info);
      /*
        Reset s_query() if changed by previous loop.
      */
      s_query.length(sizeof(stub) - 1);

      /*
        Loop forward through all tables that belong to a common database
        within the sublist of common pseudo_thread_id to create single
        DROP query.
      */
      for (;
           share && is_user_table(share) &&
             tmpkeyval(share) == m_thd->variables.pseudo_thread_id &&
             share->db.length == db.length() &&
             memcmp(share->db.str, db.ptr(), db.length()) == 0;
           share= next)
      {
        /*
          We are going to add ` around the table names and possible more
          due to special characters.
        */
        append_identifier(m_thd, &s_query, share->table_name.str,
                          strlen(share->table_name.str));
        s_query.append(',');
        next= share->next;
      }

      m_thd->clear_error();
      CHARSET_INFO *cs_save= m_thd->variables.character_set_client;
      m_thd->variables.character_set_client= system_charset_info;
      m_thd->thread_specific_used= true;

      Query_log_event qinfo(m_thd, s_query.ptr(),
                            s_query.length() - 1 /* to remove trailing ',' */,
                            false, true, false, 0);
      qinfo.db= db.ptr();
      qinfo.db_len= db.length();
      m_thd->variables.character_set_client= cs_save;

      m_thd->get_stmt_da()->set_overwrite_status(true);
      if ((error= (mysql_bin_log.write(&qinfo) || error)))
      {
        /*
          If we're here following THD::cleanup, thence the connection
          has been closed already. So lets print a message to the
          error log instead of pushing yet another error into the
          stmt_da.

          Also, we keep the error flag so that we propagate the error
          up in the stack. This way, if we're the SQL thread we notice
          that close_temporary_tables failed. (Actually, the SQL
          thread only calls close_temporary_tables while applying old
          Start_log_event_v3 events.)
        */
        sql_print_error("Failed to write the DROP statement for "
                        "temporary tables to binary log");
      }

      m_thd->get_stmt_da()->set_overwrite_status(false);
      m_thd->variables.pseudo_thread_id= save_pseudo_thread_id;
      m_thd->thread_specific_used= save_thread_specific_used;
    }
    else
    {
      next= share->next;
    }
  }

  if (!was_quote_show)
  {
    /*
      Restore option.
    */
    m_thd->variables.option_bits&= ~OPTION_QUOTE_SHOW_CREATE;
  }

  DBUG_RETURN(error);
}


/*
  Rename a temporary table.

  @param table [in]                   Table handle
  @param db [in]                      New schema name
  @param table_name [in]              New table name

  @return false                       Success
          true                        Error
*/
bool Temporary_tables::rename_table(TABLE *table,
                                    const char *db,
                                    const char *table_name)
{
  DBUG_ENTER("Temporary_tables::rename_table");

  char *key;
  uint key_length;
  TABLE_SHARE *share= table->s;

  if (!(key= (char *) alloc_root(&share->mem_root, MAX_DBKEY_LENGTH)))
  {
    DBUG_RETURN(true);
  }

  /*
    Temporary tables are renamed by simply changing their table definition key.
  */
  key_length= create_table_def_key(key, db, table_name);
  share->set_table_cache_key(key, key_length);

  DBUG_RETURN(false);
}


/*
  Drop a temporary table.

  Try to locate the table in the list of thd->temporary_tables.
  If the table is found:
   - If the table is being used by some outer statement, i.e.
     ref_count > 1, we only close the given table and return.
   - If the table is locked with LOCK TABLES or by prelocking,
     unlock it and remove it from the list of locked tables
     (THD::lock). Currently only transactional temporary tables
     are locked.
   - Close the temporary table, remove its .FRM.
   - Remove the table share from the list of temporary table shares.

  This function is used to drop user temporary tables, as well as
  internal tables created in CREATE TEMPORARY TABLE ... SELECT
  or ALTER TABLE. Even though part of the work done by this function
  is redundant when the table is internal, as long as we
  link both internal and user temporary tables into the same
  temporary tables list, it's impossible to tell here whether
  we're dealing with an internal or a user temporary table.

  @param thd   [in]                   Thread handler
  @param table [in]                   Temporary table to be deleted
  @param is_trans [out]               Is set to the type of the table:
                                      transactional (e.g. innodb) as true or
                                      non-transactional (e.g. myisam) as false.

  @retval  0  the table was found and dropped successfully.
  @retval -1  the table is in use by a outer query
*/


/*
  @return false                       Table was either dropped or closed in
                                      case multiple open tables were found
                                      referring the table share.
          true                        Error
*/
bool Temporary_tables::drop_table(TABLE *table,
                                  bool *is_trans,
                                  bool delete_in_engine)
{
  DBUG_ENTER("Temporary_tables::drop_table");

  TABLE_SHARE *share;
  handlerton *hton;
  uint ref_count= 0;
  bool result;

  DBUG_ASSERT(table);
  DBUG_PRINT("tmptable", ("Dropping table: '%s'.'%s'",
                          table->s->db.str, table->s->table_name.str));

  lock_tables();

  if (is_trans)
    *is_trans= table->file->has_transactions();

  share= table->s;
  hton= share->db_type();

  /*
    Iterate over the list of open tables to find the number of tables
    referencing this table share.
   */
  for (TABLE *tab= m_opened_tables; tab; tab= tab->next)
  {
    if (tab->s == share)
    {
      ref_count ++;
    }
  }

  DBUG_ASSERT(ref_count > 0);

  /*
    If LOCK TABLES list is not empty and contains this table, unlock the table
    and remove the table from this list.
  */
  mysql_lock_remove(m_thd, m_thd->lock, table);

  if (close_table(table))
  {
    result= true;
    goto end;
  }

  /* There are other tables referencing this table share. */
  if (ref_count > 1)
  {
    result= false;
    goto end;
  }

  if (delete_in_engine)
  {
    rm_temporary_table(hton, share->path.str);
  }

  /* Delete the share from table share list */
  unlink<TABLE_SHARE>(&m_table_shares, share);

  free_table_share(share);
  my_free(share);

  /* Decrement Slave_open_temp_table_definitions status variable count. */
  if (m_thd->rgi_slave)
  {
    thread_safe_decrement32(&slave_open_temp_table_definitions);
  }

  result= false;

end:
  unlock_tables();

  DBUG_RETURN(result);
}


/*
  Create a table definition key.

  @param key [out]                    Buffer for the key to be created (must
                                      be of size MAX_DBKRY_LENGTH)
  @param db [in]                      Database name
  @param table_name [in]              Table name

  @return                             Key length.

  @note
    The table key is create from:
    db + \0
    table_name + \0

    Additionally, we add the following to make each temporary table unique on
    the slave.

    4 bytes of master thread id
    4 bytes of pseudo thread id
*/

uint Temporary_tables::create_table_def_key(char *key, const char *db,
                                            const char *table_name)
{
  DBUG_ENTER("Temporary_tables::create_table_def_key");

  uint key_length;

  key_length= tdc_create_key(key, db, table_name);
  int4store(key + key_length, m_thd->variables.server_id);
  int4store(key + key_length + 4, m_thd->variables.pseudo_thread_id);
  key_length += TMP_TABLE_KEY_EXTRA;

  DBUG_RETURN(key_length);
}


/**
  Delete a temporary table.

  @param base [in]                    Handlerton for table to be deleted.
  @param path [in]                    Path to the table to be deleted (i.e. path
                                      to its .frm without an extension).

  @return false                       Success
          true                        Error
*/
bool Temporary_tables::rm_temporary_table(handlerton *base, const char *path)
{
  bool error= false;
  handler *file;
  char frm_path[FN_REFLEN + 1];

  DBUG_ENTER("Temporary_tables::rm_temporary_table");

  strxnmov(frm_path, sizeof(frm_path) - 1, path, reg_ext, NullS);
  if (mysql_file_delete(key_file_frm, frm_path, MYF(0)))
    error= true;

  file= get_new_handler((TABLE_SHARE*) 0, current_thd->mem_root, base);
  if (file && file->ha_delete_table(path))
  {
    error= true;
    sql_print_warning("Could not remove temporary table: '%s', error: %d",
                      path, my_errno);
  }

  delete file;
  DBUG_RETURN(error);
}


bool Temporary_tables::wait_for_prior_commit()
{
  DBUG_ENTER("Temporary_tables::wait_for_prior_commit");

  /*
    Temporary tables are not safe for parallel replication. They were
    designed to be visible to one thread only, so have no table locking.
    Thus there is no protection against two conflicting transactions
    committing in parallel and things like that.

    So for now, anything that uses temporary tables will be serialised
    with anything before it, when using parallel replication.

    TODO: We might be able to introduce a reference count or something
    on temp tables, and have slave worker threads wait for it to reach
    zero before being allowed to use the temp table. Might not be worth
    it though, as statement-based replication using temporary tables is
    in any case rather fragile.
  */
  if (m_thd->rgi_slave &&
      m_thd->rgi_slave->is_parallel_exec &&
      m_thd->wait_for_prior_commit())
  {
    DBUG_RETURN(true);
  }

  DBUG_RETURN(false);
}


void Temporary_tables::mark_tables_as_free_for_reuse() {
  TABLE *table;
  TABLE *next;

  DBUG_ENTER("mark_temp_tables_as_free_for_reuse");

  if (m_thd->query_id == 0)
  {
    /* Thread has not executed any statement and has not used any tmp tables */
    DBUG_VOID_RETURN;
  }

  lock_tables();

  if (!m_thd->temporary_tables.is_empty())
  {

    table= m_opened_tables;

    while(table) {
      next= table->next;

      if ((table->query_id == m_thd->query_id) && ! table->open_by_handler)
      {
        mysql_lock_remove(m_thd, m_thd->lock, table);
        close_table(table);
      }

      table= next;
    }
  }

  unlock_tables();

  DBUG_VOID_RETURN;
}


void Temporary_tables::lock_tables()
{
  rpl_group_info *rgi_slave= m_thd->rgi_slave;
  if (rgi_slave)
  {
    mysql_mutex_lock(&rgi_slave->rli->data_lock);
    m_table_shares= rgi_slave->rli->save_temp_table_shares;
  }
}


void Temporary_tables::unlock_tables()
{
  rpl_group_info *rgi_slave= m_thd->rgi_slave;
  if (rgi_slave)
  {
    rgi_slave->rli->save_temp_table_shares= m_table_shares;
    mysql_mutex_unlock(&rgi_slave->rli->data_lock);
  }
}

