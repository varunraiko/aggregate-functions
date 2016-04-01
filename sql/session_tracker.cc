/* Copyright (c) 2015, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */


#include "sql_plugin.h"
#include "session_tracker.h"

#include "hash.h"
#include "table.h"
#include "rpl_gtid.h"
#include "sql_class.h"
#include "sql_show.h"
#include "set_var.h"

static void store_lenenc_string(String &to, const char *from,
                                size_t length);

class Dummy_tracker : public State_tracker
{
  bool enable(THD *thd __attribute__((unused)))
  { return update(thd); }
  bool check(THD *thd __attribute__((unused)),
             set_var *var __attribute__((unused)))
  { return false; }
  bool update(THD *thd __attribute__((unused)))
  { return false; }
  bool store(THD *thd __attribute__((unused)),
             String &buf __attribute__((unused)))

  { return false; }
  void mark_as_changed(THD *thd __attribute__((unused)),
                       LEX_CSTRING *tracked_item_name __attribute__((unused)))
  {}

};

static my_bool name_array_filler(void *ptr, void *data_ptr);
/**
  Session_sysvars_tracker
  -----------------------
  This is a tracker class that enables & manages the tracking of session
  system variables. It internally maintains a hash of user supplied variable
  names and a boolean field to store if the variable was changed by the last
  statement.
*/

class Session_sysvars_tracker : public State_tracker
{
private:

  struct sysvar_node_st {
    sys_var *m_svar;
    bool m_changed;
  };

  class vars_list
  {
  private:
    /**
      Registered system variables. (@@session_track_system_variables)
      A hash to store the name of all the system variables specified by the
      user.
    */
    HASH m_registered_sysvars;
    /** Size of buffer for string representation */
    size_t buffer_length;
    /**
      The boolean which when set to true, signifies that every variable
      is to be tracked.
    */
    bool track_all;
    void init()
    {
      my_hash_init(&m_registered_sysvars,
                   &my_charset_bin,
		   4, 0, 0, (my_hash_get_key) sysvars_get_key,
		   my_free, HASH_UNIQUE);
    }
    void free_hash()
    {
      if (my_hash_inited(&m_registered_sysvars))
      {
	my_hash_free(&m_registered_sysvars);
      }
    }

    uchar* search(const sys_var *svar)
    {
      return (my_hash_search(&m_registered_sysvars, (const uchar *)&svar,
			     sizeof(sys_var *)));
    }

  public:
    vars_list() :
      buffer_length(0)
    {
      init();
    }

    size_t get_buffer_length()
    {
      DBUG_ASSERT(buffer_length != 0); // asked earlier then should
      return buffer_length;
    }
    ~vars_list()
    {
      /* free the allocated hash. */
      if (my_hash_inited(&m_registered_sysvars))
      {
	my_hash_free(&m_registered_sysvars);
      }
    }

    uchar* search(sysvar_node_st *node, const sys_var *svar)
    {
      uchar *res;
      res= search(svar);
      if (!res)
      {
	if (track_all)
	{
	  insert(node, svar);
	  return search(svar);
	}
      }
      return res;
    }

    uchar* operator[](ulong idx)
    {
      return my_hash_element(&m_registered_sysvars, idx);
    }
    bool insert(sysvar_node_st *node, const sys_var *svar);
    void reset();
    bool update(vars_list* from, THD *thd);
    bool parse_var_list(THD *thd, LEX_STRING var_list, bool throw_error,
                        const CHARSET_INFO *char_set, bool session_created);
    bool construct_var_list(char *buf, size_t buf_len);
  };
  /**
    Two objects of vars_list type are maintained to manage
    various operations.
  */
  vars_list *orig_list, *tool_list;

public:
  /** Constructor */
  Session_sysvars_tracker()
  {
    orig_list= new (std::nothrow) vars_list();
    tool_list= new (std::nothrow) vars_list();
  }

  /** Destructor */
  ~Session_sysvars_tracker()
  {
    if (orig_list)
      delete orig_list;
    if (tool_list)
      delete tool_list;
  }

  size_t get_buffer_length()
  {
    return orig_list->get_buffer_length();
  }
  bool construct_var_list(char *buf, size_t buf_len)
  {
    return orig_list->construct_var_list(buf, buf_len);
  }

  /**
    Method used to check the validity of string provided
    for session_track_system_variables during the server
    startup.
  */
  static bool server_init_check(const CHARSET_INFO *char_set, LEX_STRING var_list)
  {
    vars_list dummy;
    bool result;
    result= dummy.parse_var_list(NULL, var_list, false, char_set, true);
    return result;
  }

  void reset();
  bool enable(THD *thd);
  bool check(THD *thd, set_var *var);
  bool check_str(THD *thd, LEX_STRING val);
  bool update(THD *thd);
  bool store(THD *thd, String &buf);
  void mark_as_changed(THD *thd, LEX_CSTRING *tracked_item_name);
  /* callback */
  static uchar *sysvars_get_key(const char *entry, size_t *length,
                                my_bool not_used __attribute__((unused)));

  friend my_bool name_array_filler(void *ptr, void *data_ptr);
};



/**
  Current_schema_tracker
  ----------------------
  This is a tracker class that enables & manages the tracking of current
  schema for a particular connection.
*/

class Current_schema_tracker : public State_tracker
{
private:
  bool schema_track_inited;
  void reset();

public:

  /** Constructor */
  Current_schema_tracker()
  {
    schema_track_inited= false;
  }

  bool enable(THD *thd)
  { return update(thd); }
  bool check(THD *thd, set_var *var)
  { return false; }
  bool update(THD *thd);
  bool store(THD *thd, String &buf);
  void mark_as_changed(THD *thd, LEX_CSTRING *tracked_item_name);
};

/* To be used in expanding the buffer. */
static const unsigned int EXTRA_ALLOC= 1024;


void Session_sysvars_tracker::vars_list::reset()
{
  buffer_length= 0;
  if (m_registered_sysvars.records)
    my_hash_reset(&m_registered_sysvars);
}

/**
  This function is used to update the members of one vars_list object with
  the members from the other.

  @@param  from    Source vars_list object.
  @@param  thd     THD handle to retrive the charset in use.

  @@return    true if the m_registered_sysvars hash has any records.
              Else the value of track_all.
*/

bool Session_sysvars_tracker::vars_list::update(vars_list* from, THD *thd)
{
  reset();
  track_all= from->track_all;
  free_hash();
  buffer_length= from->buffer_length;
  m_registered_sysvars= from->m_registered_sysvars;
  from->init();
  return (m_registered_sysvars.records)? true : track_all;
}

/**
  Inserts the variable to be tracked into m_registered_sysvars hash.

  @@param   node   Node to be inserted.
  @@param   svar   address of the system variable

  @@return  false  success
            true   error
*/

bool Session_sysvars_tracker::vars_list::insert(sysvar_node_st *node,
                                                const sys_var *svar)
{
  if (!node)
  {
    if (!(node= (sysvar_node_st *) my_malloc(sizeof(sysvar_node_st), MY_WME)))
    {
      reset();
      return true;                            /* Error */
    }
  }

  node->m_svar= (sys_var *)svar;
  node->m_changed= false;
  if (my_hash_insert(&m_registered_sysvars, (uchar *) node))
  {
    /* Duplicate entry. */
    my_error(ER_DUP_LIST_ENTRY, MYF(0), svar->name.str);
    reset();
    my_free(node);
    return true;
  }                          /* Error */
  return false;
}

/**
  @brief Parse the specified system variables list. While parsing raise
         warning/error on invalid/duplicate entries.

         * In case of duplicate entry ER_DUP_LIST_ENTRY is raised.
         * In case of invalid entry a warning is raised per invalid entry.
           This is done in order to handle 'potentially' valid system
           variables from uninstalled plugins which might get installed in
           future.


  @param thd             [IN]    The thd handle.
  @param var_list        [IN]    System variable list.
  @param throw_error     [IN]    bool when set to true, returns an error
                                 in case of invalid/duplicate values.
  @param char_set	 [IN]	 charecter set information used for string
				 manipulations.
  @param session_created [IN]    bool variable which says if the parse is
                                 already executed once. The mutex on variables
				 is not acquired if this variable is false.

  @return
    true                    Error
    false                   Success
*/
bool Session_sysvars_tracker::vars_list::parse_var_list(THD *thd,
                                                        LEX_STRING var_list,
                                                        bool throw_error,
							const CHARSET_INFO *char_set,
							bool session_created)
{
  const char separator= ',';
  char *token, *lasts= NULL;
  size_t rest= var_list.length;

  if (!var_list.str || var_list.length == 0)
  {
    buffer_length= 1;
    return false;
  }

  if(!strcmp(var_list.str,(const char *)"*"))
  {
    track_all= true;
    buffer_length= 2;
    return false;
  }

  buffer_length= var_list.length + 1;
  token= var_list.str;

  track_all= false;
  /*
    If Lock to the plugin mutex is not acquired here itself, it results
    in having to acquire it multiple times in find_sys_var_ex for each
    token value. Hence the mutex is handled here to avoid a performance
    overhead.
  */
  if (!thd || session_created)
    mysql_mutex_lock(&LOCK_plugin);
  for (;;)
  {
    sys_var *svar;
    LEX_STRING var;

    lasts= (char *) memchr(token, separator, rest);

    var.str= token;
    if (lasts)
    {
      var.length= (lasts - token);
      rest-= var.length + 1;
    }
    else
      var.length= rest;

    /* Remove leading/trailing whitespace. */
    trim_whitespace(char_set, &var);

    if ((svar= find_sys_var_ex(thd, var.str, var.length, throw_error, true)))
    {
      if (insert(NULL, svar) == TRUE)
        goto error;
    }
    else if (throw_error && session_created && thd)
    {
      push_warning_printf(thd, Sql_condition::WARN_LEVEL_WARN,
                          ER_WRONG_VALUE_FOR_VAR,
                          "%.*s is not a valid system variable and will"
                          "be ignored.", (int)var.length, token);
    }
    else
      goto error;

    if (lasts)
      token= lasts + 1;
    else
      break;
  }
  if (!thd || session_created)
    mysql_mutex_unlock(&LOCK_plugin);

  return false;

error:
  if (!thd || session_created)
    mysql_mutex_unlock(&LOCK_plugin);
  return true;
}

struct name_array_filler_data
{
  LEX_CSTRING **names;
  uint idx;

};

static my_bool name_array_filler(void *ptr, void *data_ptr)
{
  Session_sysvars_tracker::sysvar_node_st *node=
    (Session_sysvars_tracker::sysvar_node_st *)ptr;
  name_array_filler_data *data= (struct name_array_filler_data *)data_ptr;
  data->names[data->idx++]= &node->m_svar->name;
  return FALSE;
}

static int name_array_sorter(const void *a, const void *b)
{
  LEX_CSTRING **an= (LEX_CSTRING **)a, **bn=(LEX_CSTRING **)b;
  size_t min= MY_MIN((*an)->length, (*bn)->length);
  int res= strncmp((*an)->str, (*bn)->str, min);
  if (res == 0)
    res= ((int)(*bn)->length)- ((int)(*an)->length);
  return res;
}

bool Session_sysvars_tracker::vars_list::construct_var_list(char *buf,
                                                            size_t buf_len)
{
  struct name_array_filler_data data;
  size_t left= buf_len;
  size_t names_size= m_registered_sysvars.records * sizeof(LEX_CSTRING *);
  const char separator= ',';

  if (unlikely(buf_len < 1))
    return true;

  if (unlikely(track_all))
  {
    if (buf_len < 2)
      return true;
    buf[0]= '*';
    buf[1]= '\0';
    return false;
  }

  if (m_registered_sysvars.records == 0)
  {
    buf[0]= '\0';
    return false;
  }

  data.names= (LEX_CSTRING**)my_safe_alloca(names_size);

  if (unlikely(!data.names))
    return true;

  data.idx= 0;
  my_hash_iterate(&m_registered_sysvars, &name_array_filler, &data);
  DBUG_ASSERT(data.idx == m_registered_sysvars.records);

  my_qsort(data.names, m_registered_sysvars.records, sizeof(LEX_CSTRING *),
           &name_array_sorter);

  for(uint i= 0; i < m_registered_sysvars.records; i++)
  {
    LEX_CSTRING *nm= data.names[i];
    size_t ln= nm->length + 1;
    if (ln > left)
    {
      my_safe_afree(data.names, names_size);
      return true;
    }
    memcpy(buf, nm->str, nm->length);
    buf[nm->length]= separator;
    buf+= ln;
    left-= ln;
  }

  buf--; buf[0]= '\0';
  my_safe_afree(data.names, names_size);

  return false;
}

/**
  @brief It is responsible for enabling this tracker when a session starts.
         During the initialization, a session's system variable gets a copy
         of the global variable. The new value of session_track_system_variables
         is then verified & tokenized to create a hash, which is then updated to
	 orig_list which represents all the systems variables to be tracked.

  @param thd    [IN]        The thd handle.

  @return
    true                    Error
    false                   Success
*/

bool Session_sysvars_tracker::enable(THD *thd)
{
  sys_var *svar;

  mysql_mutex_lock(&LOCK_plugin);
  svar= find_sys_var_ex(thd, SESSION_TRACK_SYSTEM_VARIABLES_NAME.str,
                        SESSION_TRACK_SYSTEM_VARIABLES_NAME.length,
                        false, true);
  DBUG_ASSERT(svar);

  set_var tmp(thd, SHOW_OPT_GLOBAL, svar, &null_lex_str, NULL);
  svar->session_save_default(thd, &tmp);

  if (tool_list->parse_var_list(thd, tmp.save_result.string_value,
                                true, thd->charset(), false) == true)
  {
    mysql_mutex_unlock(&LOCK_plugin);
    return true;
  }
  mysql_mutex_unlock(&LOCK_plugin);
  m_enabled= orig_list->update(tool_list, thd);

  return false;
}


/**
  @brief Check if any of the system variable name(s) in the given list of
         system variables is duplicate/invalid.

         When the value of @@session_track_system_variables system variable is
         updated, the new value is first verified in this function (called from
         ON_CHECK()) and a hash is populated in tool_list.

  @note This function is called from the ON_CHECK() function of the
        session_track_system_variables' sys_var class.

  @param thd    [IN]        The thd handle.
  @param var    [IN]        A pointer to set_var holding the specified list of
                            system variable names.

  @return
    true                    Error
    false                   Success
*/

inline bool Session_sysvars_tracker::check(THD *thd, set_var *var)
{
  return check_str(thd, var->save_result.string_value);
}

inline bool Session_sysvars_tracker::check_str(THD *thd, LEX_STRING val)
{
  tool_list->reset();
  return tool_list->parse_var_list(thd, val, true,
                                   thd->charset(), true);
}


/**
  @brief Once the value of the @@session_track_system_variables has been
         successfully updated, this function calls
	 Session_sysvars_tracker::vars_list::update updating the hash in
         orig_list which represents the system variables to be tracked.

  @note This function is called from the ON_UPDATE() function of the
        session_track_system_variables' sys_var class.

  @param thd    [IN]        The thd handle.

  @return
    true                    Error
    false                   Success
*/

bool Session_sysvars_tracker::update(THD *thd)
{
  m_enabled= orig_list->update(tool_list, thd);
  return false;
}


/**
  @brief Store the data for changed system variables in the specified buffer.
         Once the data is stored, we reset the flags related to state-change
         (see reset()).

  @param thd [IN]           The thd handle.
  @paran buf [INOUT]        Buffer to store the information to.

  @return
    false                   Success
    true                    Error
*/

bool Session_sysvars_tracker::store(THD *thd, String &buf)
{
  char val_buf[1024];
  const char *value;
  sysvar_node_st *node;
  SHOW_VAR *show;
  const CHARSET_INFO *charset;
  size_t val_length, length;
  uchar *to;
  int idx= 0;

  if (!(show= (SHOW_VAR *) thd->alloc(sizeof(SHOW_VAR))))
    return true;

  /* As its always system variable. */
  show->type= SHOW_SYS;

  while ((node= (sysvar_node_st *) (*orig_list)[idx]))
  {
    if (node->m_changed)
    {
      sys_var *svar= node->m_svar;
      show->name= svar->name.str;
      show->value= (char *) svar;

      value= get_one_variable(thd, show, OPT_SESSION, show->type, NULL,
                              &charset, val_buf, &val_length);

      length= net_length_size(svar->name.length) +
              svar->name.length +
              net_length_size(val_length) +
              val_length;

      to= (uchar *) buf.prep_append(net_length_size(length) + 1, EXTRA_ALLOC);

      /* Session state type (SESSION_TRACK_SYSTEM_VARIABLES) */
      to= net_store_length(to, (ulonglong)SESSION_TRACK_SYSTEM_VARIABLES);

      /* Length of the overall entity. */
      net_store_length(to, (ulonglong)length);

      /* System variable's name (length-encoded string). */
      store_lenenc_string(buf, svar->name.str,
                          svar->name.length);

      /* System variable's value (length-encoded string). */
      store_lenenc_string(buf, value, val_length);
    }
    ++ idx;
  }

  reset();

  return false;
}


/**
  @brief Mark the system variable with the specified name as changed.
  @param               [IN] pointer on a variable

  @return                   void
*/

void Session_sysvars_tracker::mark_as_changed(THD *thd,
                                              LEX_CSTRING *var)
{
  sysvar_node_st *node= NULL;
  sys_var *svar= (sys_var *)var;
  /*
    Check if the specified system variable is being tracked, if so
    mark it as changed and also set the class's m_changed flag.
  */
  if ((node= (sysvar_node_st *) (orig_list->search(node, svar))))
  {
    node->m_changed= true;
    m_changed= true;
    /* do not cache the statement when there is change in session state */
    thd->lex->safe_to_cache_query= 0;
  }
}


/**
  @brief Supply key to the hash implementation (to be used internally by the
         implementation).

  @param entry  [IN]        A single entry.
  @param length [OUT]       Length of the key.
  @param not_used           Unused.

  @return                   Pointer to the key buffer.
*/

uchar *Session_sysvars_tracker::sysvars_get_key(const char *entry,
                                                size_t *length,
                                                my_bool not_used __attribute__((unused)))
{
  *length= sizeof(sys_var *);
  return (uchar *) &(((sysvar_node_st *) entry)->m_svar);
}


/**
  @brief Prepare/reset the m_registered_sysvars hash for next statement.

  @return                   void
*/

void Session_sysvars_tracker::reset()
{
  sysvar_node_st *node;
  int idx= 0;

  while ((node= (sysvar_node_st *) (*orig_list)[idx]))
  {
    node->m_changed= false;
    ++ idx;
  }
  m_changed= false;
}

static Session_sysvars_tracker* sysvar_tracker(THD *thd)
{
  return (Session_sysvars_tracker*)
    thd->session_tracker.get_tracker(SESSION_SYSVARS_TRACKER);
}

bool sysvartrack_validate_value(THD *thd, const char *str, size_t len)
{
  LEX_STRING tmp= {(char *)str, len};
  return sysvar_tracker(thd)->check_str(thd, tmp);
}
bool sysvartrack_update(THD *thd)
{
  return sysvar_tracker(thd)->update(thd);
}
size_t sysvartrack_value_len(THD *thd)
{
  return sysvar_tracker(thd)->get_buffer_length();
}
bool sysvartrack_value_construct(THD *thd, char *val, size_t len)
{
  return sysvar_tracker(thd)->construct_var_list(val, len);
}

///////////////////////////////////////////////////////////////////////////////

/**
  @brief Enable/disable the tracker based on @@session_track_schema's value.

  @param thd [IN]           The thd handle.

  @return
    false (always)
*/

bool Current_schema_tracker::update(THD *thd)
{
  m_enabled= (thd->variables.session_track_schema)? true: false;
  return false;
}


/**
  @brief Store the schema name as length-encoded string in the specified
         buffer.  Once the data is stored, we reset the flags related to
         state-change (see reset()).


  @param thd [IN]           The thd handle.
  @paran buf [INOUT]        Buffer to store the information to.

  @return
    false                   Success
    true                    Error
*/

bool Current_schema_tracker::store(THD *thd, String &buf)
{
  ulonglong db_length, length;

  length= db_length= thd->db_length;
  length += net_length_size(length);

  uchar *to= (uchar *) buf.prep_append(net_length_size(length) + 1,
                                       EXTRA_ALLOC);

  /* Session state type (SESSION_TRACK_SCHEMA) */
  to= net_store_length(to, (ulonglong)SESSION_TRACK_SCHEMA);

  /* Length of the overall entity. */
  to= net_store_length(to, length);

  /* Length of the changed current schema name. */
  net_store_length(to, db_length);

  /* Current schema name (length-encoded string). */
  store_lenenc_string(buf, thd->db, thd->db_length);

  reset();

  return false;
}


/**
  @brief Mark the tracker as changed.

  @param name [IN]          Always null.

  @return void
*/

void Current_schema_tracker::mark_as_changed(THD *thd,
                                             LEX_CSTRING *tracked_item_name
                                             __attribute__((unused)))
{
  m_changed= true;
  thd->lex->safe_to_cache_query= 0;
}


/**
  @brief Reset the m_changed flag for next statement.

  @return                   void
*/

void Current_schema_tracker::reset()
{
  m_changed= false;
}


///////////////////////////////////////////////////////////////////////////////
 
/** Constructor */
Session_state_change_tracker::Session_state_change_tracker()
{
  m_changed= false;
}

/**
  @brief Initiate the value of m_enabled based on
  @@session_track_state_change value.

  @param thd [IN]           The thd handle.
  @return                   false (always)

**/

bool Session_state_change_tracker::enable(THD *thd)
{
  m_enabled= (thd->variables.session_track_state_change)? true: false;
  return false;
}

/**
  @Enable/disable the tracker based on @@session_track_state_change value.

  @param thd [IN]           The thd handle.
  @return                   false (always)

**/

bool Session_state_change_tracker::update(THD *thd)
{
  return enable(thd);
}

/**
  @brief Store the 1byte boolean flag in the specified buffer. Once the
         data is stored, we reset the flags related to state-change. If
         1byte flag valie is 1 then there is a session state change else
         there is no state change information.

  @param thd [IN]           The thd handle.
  @paran buf [INOUT]        Buffer to store the information to.

  @return
    false                   Success
    true                    Error
**/

bool Session_state_change_tracker::store(THD *thd, String &buf)
{
  /* since its a boolean tracker length is always 1 */
  const ulonglong length= 1;

  uchar *to= (uchar *) buf.prep_append(3,EXTRA_ALLOC);

  /* format of the payload is as follows:
     [ tracker type] [length] [1 byte flag] */

  /* Session state type (SESSION_TRACK_STATE_CHANGE) */
  to= net_store_length(to, (ulonglong)SESSION_TRACK_STATE_CHANGE);

  /* Length of the overall entity it is always 1 byte */
  to= net_store_length(to, length);

  /* boolean tracker will go here */
  *to= (is_state_changed(thd) ? '1' : '0');

  reset();

  return false;
}

/**
  @brief Mark the tracker as changed and associated session
         attributes accordingly.

  @param name [IN]          Always null.
  @return void
*/

void Session_state_change_tracker::mark_as_changed(THD *thd,
                                                   LEX_CSTRING *tracked_item_name)
{
  /* do not send the boolean flag for the tracker itself
     in the OK packet */
  if(tracked_item_name &&
     (strncmp(tracked_item_name->str, "session_track_state_change", 26) == 0))
    m_changed= false;
  else
  {
    m_changed= true;
    thd->lex->safe_to_cache_query= 0;
  }
}

/**
  @brief Reset the m_changed flag for next statement.

  @return                   void
*/

void Session_state_change_tracker::reset()
{
  m_changed= false;
}

/**
  @brief find if there is a session state change

  @return
  true  - if there is a session state change
  false - if there is no session state change
**/

bool Session_state_change_tracker::is_state_changed(THD* thd)
{
  return m_changed;
}

///////////////////////////////////////////////////////////////////////////////

/**
  @brief Initialize session tracker objects.

  @param char_set [IN]      The character set info.

  @return                   void
*/

void Session_tracker::init()
{
  m_trackers[SESSION_SYSVARS_TRACKER]=
    new (std::nothrow) Session_sysvars_tracker();
  m_trackers[CURRENT_SCHEMA_TRACKER]=
    new (std::nothrow) Current_schema_tracker;
  m_trackers[SESSION_STATE_CHANGE_TRACKER]=
    new (std::nothrow) Session_state_change_tracker;
  m_trackers[SESSION_GTIDS_TRACKER]=
    new (std::nothrow) Dummy_tracker;
  m_trackers[TRANSACTION_INFO_TRACKER]=
    new (std::nothrow) Dummy_tracker;
}

/**
  @brief Enables the tracker objects.

  @param thd [IN]    The thread handle.

  @return            void
*/
void Session_tracker::enable(THD *thd)
{
  for (int i= 0; i <= SESSION_TRACKER_END; i ++)
    m_trackers[i]->enable(thd);
}

/**
  @brief Method called during the server startup to verify the contents
         of @@session_track_system_variables.

  @return   false           Success
            true            failure
*/
bool Session_tracker::server_boot_verify(const CHARSET_INFO *char_set)
{
  Session_sysvars_tracker *server_tracker;
  bool result;
  sys_var *svar= find_sys_var_ex(NULL, SESSION_TRACK_SYSTEM_VARIABLES_NAME.str,
                                 SESSION_TRACK_SYSTEM_VARIABLES_NAME.length,
                                 false, true);
  DBUG_ASSERT(svar);
  set_var tmp(NULL, SHOW_OPT_GLOBAL, svar, &null_lex_str, NULL);
  svar->session_save_default(NULL, &tmp);
  server_tracker= new (std::nothrow) Session_sysvars_tracker();
  result= server_tracker->server_init_check(char_set,
                                            tmp.save_result.string_value);
  my_free(tmp.save_result.string_value.str);
  delete server_tracker;
  return result;
}



/**
  @brief Returns the pointer to the tracker object for the specified tracker.

  @param tracker [IN]       Tracker type.

  @return                   Pointer to the tracker object.
*/

State_tracker *
Session_tracker::get_tracker(enum_session_tracker tracker) const
{
  return m_trackers[tracker];
}


/**
  @brief Checks if m_enabled flag is set for any of the tracker objects.

  @return
    true  - At least one of the trackers is enabled.
    false - None of the trackers is enabled.

*/

bool Session_tracker::enabled_any()
{
  for (int i= 0; i <= SESSION_TRACKER_END; i ++)
  {
    if (m_trackers[i]->is_enabled())
      return true;
  }
  return false;
}

/**
  @brief Checks if m_changed flag is set for any of the tracker objects.

  @return
    true                    At least one of the entities being tracker has
                            changed.
    false                   None of the entities being tracked has changed.
*/

bool Session_tracker::changed_any()
{
  for (int i= 0; i <= SESSION_TRACKER_END; i ++)
  {
    if (m_trackers[i]->is_changed())
      return true;
  }
  return false;
}


/**
  @brief Store all change information in the specified buffer.

  @param thd [IN]           The thd handle.
  @param buf [OUT]          Reference to the string buffer to which the state
                            change data needs to be written.

  @return                   void
*/

void Session_tracker::store(THD *thd, String &buf)
{
  /* Temporary buffer to store all the changes. */
  String temp;
  size_t length;

  /* Get total length. */
  for (int i= 0; i <= SESSION_TRACKER_END; i ++)
  {
    if (m_trackers[i]->is_changed())
      m_trackers[i]->store(thd, temp);
  }

  length= temp.length();
  /* Store length first.. */
  char *to= buf.prep_append(net_length_size(length), EXTRA_ALLOC);
  net_store_length((uchar *) to, length);

  /* .. and then the actual info. */
  buf.append(temp);
}


/**
  @brief Stores the given string in length-encoded format into the specified
         buffer.

  @param to     [IN]        Buffer to store the given string in.
  @param from   [IN]        The give string to be stored.
  @param length [IN]        Length of the above string.

  @return                   void.
*/

static
void store_lenenc_string(String &to, const char *from, size_t length)
{
  char *ptr;
  ptr= to.prep_append(net_length_size(length), EXTRA_ALLOC);
  net_store_length((uchar *) ptr, length);
  to.append(from, length);
}

