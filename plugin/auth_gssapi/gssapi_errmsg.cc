#include <gssapi.h>
#include <string.h>
void gssapi_errmsg(OM_uint32 major, OM_uint32 minor, char *buf, size_t size)
{
  OM_uint32 message_context;
  OM_uint32 status_code;
  OM_uint32 maj_status;
  OM_uint32 min_status;
  gss_buffer_desc status_string;
  char *p= buf;
  char *end= buf + size - 1;
  int types[] = {GSS_C_GSS_CODE,GSS_C_MECH_CODE};

  for(int i= 0; i < 2;i++)
  {
    message_context= 0;
    status_code= types[i] == GSS_C_GSS_CODE?major:minor;

    if(!status_code)
      continue;
    do
    {
      maj_status = gss_display_status(
        &min_status,
        status_code,
        types[i],
        GSS_C_NO_OID,
        &message_context,
        &status_string);

      if(maj_status)
        break;

      if(p + status_string.length + 2 < end)
      {
        memcpy(p,status_string.value, status_string.length);
        p += status_string.length;
        *p++ = '.';
        *p++ = ' ';
      }

      gss_release_buffer(&min_status, &status_string);
    }
    while (message_context != 0);
  }
  *p= 0;
}
