bin_PROGRAMS = chxhttp

chxhttp_SOURCES = \
    ./application_init.cpp \
    ./wildcard.cpp \
    ./log.cpp \
    ./h1_1.cpp \
    ./tail_fn.cpp \
    ./main.cpp \
    ./log_backend.cpp \
    ./utility/sha256.cpp \
    ./utility/base64.cpp \
    ./h2/h2.cpp \
    ./h2/h2_log.cpp \
    ./h2/hpack.cpp \
    ./impl/static_file.cpp \
    ./impl/static_file_resp.cpp \
    ./impl/request_preprocess.cpp \
    ./impl/work.cpp \
    ./http_related/mime.cpp \
    ./http_related/etag.cpp \
    ./http_related/byte_range.cpp \
    ./http_related/media_type.cpp


chxhttp_CXXFLAGS = -I../include -I../chxnet/include -I../chxlog/include \
    $(CHXHTTP_CXXFLAGS)
chxhttp_LDADD = $(CHXHTTP_LDADD)
chxhttp_LDFLAGS = $(CHXHTTP_LDFLAGS)
