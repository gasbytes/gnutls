/*
 * Copyright (C) 2009-2012 Free Software Foundation, Inc.
 *
 * Author: Jonathan Bastien-Filiatrault
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#ifndef DTLS_H
# define DTLS_H

#include <config.h>
#include <gnutls_int.h>
#include <gnutls_buffers.h>
#include <gnutls_mbuffers.h>
#include <gnutls_constate.h>
#include <timespec.h>

int _dtls_transmit(gnutls_session_t session);
int _dtls_retransmit(gnutls_session_t session);
int _dtls_record_check(struct record_parameters_st *rp, uint64 * _seq);
void _dtls_reset_hsk_state(gnutls_session_t session);

#define MAX_DTLS_TIMEOUT 60000

/* returns a-b in ms */
inline static unsigned int timespec_sub_ms(struct timespec *a, struct timespec *b)
{
  return (a->tv_sec * 1000 + a->tv_nsec / (1000 * 1000) -
          (b->tv_sec * 1000 + b->tv_nsec / (1000 * 1000)));
}

#define RETURN_DTLS_EAGAIN_OR_TIMEOUT(session, r) { \
  struct timespec now; \
  unsigned int diff; \
  gettime(&now); \
   \
  diff = timespec_sub_ms(&now, &session->internals.dtls.handshake_start_time); \
  if (diff > session->internals.dtls.total_timeout_ms) \
    { \
      _gnutls_dtls_log("Session timeout: %u ms\n", diff); \
      return gnutls_assert_val(GNUTLS_E_TIMEDOUT); \
    } \
  else \
    { \
      int rr; \
      if (r != GNUTLS_E_INTERRUPTED) rr = GNUTLS_E_AGAIN; \
      else rr = r; \
      if (session->internals.dtls.blocking != 0) \
        millisleep(50); \
      return gnutls_assert_val(rr); \
    } \
  }


int _dtls_wait_and_retransmit(gnutls_session_t session);

/* returns true or false depending on whether we need to
 * handle asynchronously handshake data.
 */
inline static int _dtls_is_async(gnutls_session_t session)
{
  if ((session->security_parameters.entity == GNUTLS_SERVER && session->internals.resumed == RESUME_FALSE) ||
         (session->security_parameters.entity == GNUTLS_CLIENT && session->internals.resumed == RESUME_TRUE))
    return 1;
  else
    return 0;
}

inline static void _dtls_async_timer_init(gnutls_session_t session)
{
  if (_dtls_is_async(session))
    {
      _gnutls_dtls_log ("DTLS[%p]: Initializing timer for handshake state.\n", session);
      session->internals.dtls.async_term = gnutls_time(0) + MAX_DTLS_TIMEOUT/1000;
    }
  else
    {
      _dtls_reset_hsk_state(session);
      _gnutls_handshake_io_buffer_clear (session);
      _gnutls_epoch_gc(session);
      session->internals.dtls.async_term = 0;
    }
}

inline static void _dtls_async_timer_delete(gnutls_session_t session)
{
  if (session->internals.dtls.async_term != 0)
    {
      _gnutls_dtls_log ("DTLS[%p]: Deinitializing handshake state.\n", session);
      session->internals.dtls.async_term = 0; /* turn off "timer" */

      _dtls_reset_hsk_state(session);
      _gnutls_handshake_io_buffer_clear (session);
      _gnutls_epoch_gc(session);
    }
}

/* Checks whether it is time to terminate the timer
 */
inline static void _dtls_async_timer_check(gnutls_session_t session)
{
  if (!IS_DTLS(session))
    return;

  if (session->internals.dtls.async_term != 0)
    {
      time_t now = time(0);
      
      /* check if we need to expire the queued handshake data */
      if (now > session->internals.dtls.async_term)
        {
          _dtls_async_timer_delete(session);
        }
    }
}

/* Returns non-zero if the async timer is active */
inline static int _dtls_async_timer_active(gnutls_session_t session)
{
  if (!IS_DTLS(session))
    return 0;

  return session->internals.dtls.async_term;
}

#endif
