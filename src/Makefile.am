bin_PROGRAMS = chxhttp

chxhttp_SOURCES = \
    log_backend.cpp \
    wildcard.cpp \
    log.cpp \
    main.cpp \
    application_init.cpp \
    http_related/mime.cpp \
    http_related/byte_range.cpp \
    http_related/etag.cpp \
    http_related/media_type.cpp \
    utility/sha256.cpp \
    utility/base64.cpp \
    impl/server.cpp \
    impl/static_file_service.cpp


chxhttp_CXXFLAGS = -I../include -I../chxnet/include -I../chxlog/include \
    $(CHXHTTP_CXXFLAGS)
chxhttp_LDADD = $(CHXHTTP_LDADD)
chxhttp_LDFLAGS = $(CHXHTTP_LDFLAGS)
