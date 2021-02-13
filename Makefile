PROJECT = inet_tcp_proxy_dist
PROJECT_DESCRIPTION = Erlang distribution proxy to simulate network failures
PROJECT_VERSION = 0.1.0

include $(if $(ERLANG_MK_FILENAME),$(ERLANG_MK_FILENAME),erlang.mk)
