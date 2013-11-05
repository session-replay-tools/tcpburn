bin_PROGRAMS=gryphon
gryphon_SOURCES=\
                gryphon.h\
                tc_user.c tc_user.h\
                tc_manager.c tc_manager.h\
                tc_packets_module.c tc_packets_module.h\
                tc_message_module.c tc_message_module.h\
                main.c
gryphon_LDADD=\
               ../core/libcore.a\
               ../util/libutil.a\
               ../event/libevent.a\
               ../communication/libcommunication.a\
               -lm
