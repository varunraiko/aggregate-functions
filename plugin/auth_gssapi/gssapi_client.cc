#include <gssapi/gssapi.h>
#include <string.h>
#include <stdio.h>
#include <mysql/plugin_auth.h>
#include <mysqld_error.h>
#include <mysql.h>
#include "gssapi_errmsg.h"

extern void log_client_error(MYSQL *mysql,const char *fmt,...);


/* This sends the error to the client */
static void log_error(MYSQL *mysql, OM_uint32 major, OM_uint32 minor, const char *msg)
{
  if (GSS_ERROR(major))
  {
    char sysmsg[1024];
    gssapi_errmsg(major, minor, sysmsg, sizeof(sysmsg));
    log_client_error(mysql,
      "Client GSSAPI error (major %u, minor %u) : %s - %s",
       major, minor, msg, sysmsg);
  }
  else
  {
    log_client_error(mysql, "Client GSSAPI error : %s", msg);
  }
}

int auth_client(char *principal_name, char *mech, MYSQL *mysql, MYSQL_PLUGIN_VIO *vio)
{

  int ret= CR_ERROR;
  OM_uint32 major= 0, minor= 0;
  gss_ctx_id_t ctxt= GSS_C_NO_CONTEXT;
  gss_name_t service_name= GSS_C_NO_NAME;

  if (principal_name && principal_name[0])
  {
    /* import principal from plain text */
    gss_buffer_desc principal_name_buf;
    principal_name_buf.length= strlen(principal_name);
    principal_name_buf.value= (void *) principal_name;
    major= gss_import_name(&minor, &principal_name_buf, GSS_C_NT_USER_NAME, &service_name);
    if (GSS_ERROR(major))
    {
      log_error(mysql, major, minor, "gss_import_name");
      return CR_ERROR;
    }
  }

  gss_buffer_desc input= {0,0};
  do
  {
    gss_buffer_desc output= {0,0};
    major= gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &ctxt, service_name,
                                GSS_C_NO_OID, 0, 0, GSS_C_NO_CHANNEL_BINDINGS,
                                &input, NULL, &output, NULL, NULL);
    if (output.length)
    {
      /* send credential */
      if(vio->write_packet(vio, (unsigned char *)output.value, output.length))
      {
        /* Server error packet contains detailed message. */
        ret= CR_OK_HANDSHAKE_COMPLETE;
        gss_release_buffer (&minor, &output);
        goto cleanup;
      }
    }
    gss_release_buffer (&minor, &output);

    if (GSS_ERROR(major))
    {
       log_error(mysql, major, minor,"gss_init_sec_context");
       goto cleanup;
    }

    if (major & GSS_S_CONTINUE_NEEDED)
    {
      int len= vio->read_packet(vio, (unsigned char **) &input.value);
      if (len <= 0)
      {
        /* Server error packet contains detailed message. */
        ret= CR_OK_HANDSHAKE_COMPLETE;
        goto cleanup;
      }
      input.length= len;
    }
  } while (major & GSS_S_CONTINUE_NEEDED);

  ret= CR_OK;

cleanup:
  if (service_name != GSS_C_NO_NAME)
    gss_release_name(&minor, &service_name);
  if (ctxt != GSS_C_NO_CONTEXT)
    gss_delete_sec_context(&minor, &ctxt, GSS_C_NO_BUFFER);

  return ret;
}
