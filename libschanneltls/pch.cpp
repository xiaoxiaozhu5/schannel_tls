// pch.cpp: source file corresponding to the pre-compiled header

#include "pch.h"

// When you are using pre-compiled headers, this source file is necessary for compilation to succeed.
wchar_t *curlx_convert_UTF8_to_wchar(const char *str_utf8)
{
  wchar_t *str_w = NULL;

  if(str_utf8) {
    int str_w_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                        str_utf8, -1, NULL, 0);
    if(str_w_len > 0) {
      str_w = (wchar_t*)malloc(str_w_len * sizeof(wchar_t));
      if(str_w) {
        if(MultiByteToWideChar(CP_UTF8, 0, str_utf8, -1, str_w,
                               str_w_len) == 0) {
          free(str_w);
          return NULL;
        }
      }
    }
  }

  return str_w;
}

char *curlx_convert_wchar_to_UTF8(const wchar_t *str_w)
{
  char *str_utf8 = NULL;

  if(str_w) {
    int bytes = WideCharToMultiByte(CP_UTF8, 0, str_w, -1,
                                    NULL, 0, NULL, NULL);
    if(bytes > 0) {
      str_utf8 = (char*)malloc(bytes);
      if(str_utf8) {
        if(WideCharToMultiByte(CP_UTF8, 0, str_w, -1, str_utf8, bytes,
                               NULL, NULL) == 0) {
          free(str_utf8);
          return NULL;
        }
      }
    }
  }

  return str_utf8;
}

unsigned long curlx_uztoul(size_t uznum)
{
#ifdef __INTEL_COMPILER
# pragma warning(push)
# pragma warning(disable:810) /* conversion may lose significant bits */
#endif

#if ULONG_MAX < SIZE_T_MAX
  DEBUGASSERT(uznum <= (size_t) CURL_MASK_ULONG);
#endif
  return (unsigned long)(uznum & (size_t) CURL_MASK_ULONG);

#ifdef __INTEL_COMPILER
# pragma warning(pop)
#endif
}

#define LOG_MAXBUF_SIZE 2048
void debug(const char* file, int line, const char* format, ...)
{
	va_list va;
	va_start(va, format);
	const CHAR* pFileStr = nullptr;
	char szLogBuff[LOG_MAXBUF_SIZE] = { 0 };
	pFileStr = strrchr(file, '\\');
	pFileStr = (pFileStr == NULL) ? file : pFileStr + 1;
	int num_write = snprintf(szLogBuff, LOG_MAXBUF_SIZE - 1, "[%s:%d] ", pFileStr, line);
	vsnprintf(szLogBuff + num_write, LOG_MAXBUF_SIZE - num_write, format, va);
	OutputDebugStringA(szLogBuff);
	va_end(va);
}

void debug_w(const wchar_t* file, int line, const wchar_t* format, ...)
{
	va_list va;
	va_start(va, format);
	const WCHAR* pFileStr = nullptr;
	WCHAR szLogBuff[LOG_MAXBUF_SIZE] = { 0 };
	pFileStr = wcsrchr(file, '\\');
	pFileStr = (pFileStr == NULL) ? file : pFileStr + 1;
	int num_write = swprintf_s(szLogBuff, LOG_MAXBUF_SIZE - 1, L"[%s:%d] ", pFileStr, line);
	vswprintf(szLogBuff + num_write, LOG_MAXBUF_SIZE - num_write, format, va);
	OutputDebugStringW(szLogBuff);
	va_end(va);
}

/*
 * Lock shared SSL session data
 */
void Curl_ssl_sessionid_lock(struct Curl_easy *data)
{
  if(SSLSESSION_SHARED(data))
    Curl_share_lock(data, CURL_LOCK_DATA_SSL_SESSION, CURL_LOCK_ACCESS_SINGLE);
}
