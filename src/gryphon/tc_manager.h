#ifndef  TC_MANAGER_INCLUDED
#define  TC_MANAGER_INCLUDED

#include <xcopy.h>
#include <gryphon.h>

int  gryphon_init(tc_event_loop_t *event_loop);
void gryphon_over(const int sig);
void gryphon_release_resources();

#endif   /* ----- #ifndef TC_MANAGER_INCLUDED ----- */

