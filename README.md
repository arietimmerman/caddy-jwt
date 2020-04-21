# JWT module for the Caddy 2

A simple module that allows protecting your resourcing by requiring providing a valid JWT.

__WARNING:__ This is work in progress. Do not use this on a production server.

## Usage

~~~
jwt {
    path /
    except /login
    redirect /login
    secret {$SECRET}
}
~~~

## Example

An example can be found in the `example` directory. This is how to run it.

~~~
cd example
go run main.go run
~~~
