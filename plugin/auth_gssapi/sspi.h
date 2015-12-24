#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <SecExt.h>
#include <stdarg.h>
#include <stdio.h>

#define SSPI_MAX_TOKEN_SIZE 50000
#define SEC_ERROR(err) (err < 0)
extern void sspi_errmsg(int err, char *buf, size_t size);