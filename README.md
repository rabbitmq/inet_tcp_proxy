# inet_tcp_proxy

## What is This?

This is a set of utilities that can be used to simulate [some types of] network partitions
in an distributed Erlang cluster, originally used in RabbitMQ integration tests.

This proxy is not as comprehensive as [Toxiproxy](https://github.com/Shopify/toxiproxy) or similar tools;
it is, however, very easy to embed into Erlang integration tests, and it is sufficient for some
test suites.
