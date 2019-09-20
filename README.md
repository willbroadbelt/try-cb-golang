try-cb-golang
===============

A sample application and dataset for getting started with Couchbase 6.5 or later.  The application runs a single page
UI for demonstrating query capabilities.   The application uses Couchbase Server +  Node.js + Express + Angular and
boostrap.   The application is a flight planner that allows the user to search for and select a flight route (including
return flight) based on airports and dates. Airport selection is done dynamically using an angular typeahead bound to cb
server query.   Date selection uses date time pickers and then searches for applicable air flight routes from a
previously populated database.  You additionally can use Full-Text Search to perform hotel searches.

## Prerequisites
The following pieces need to be in place in order to run the application.

1. Couchbase Server 6.5.0
2. Go 1.6+
3. The gocb SDK2.0+(alpha)


## Running the Application
To run the application, you find need to install Couchbase. You will need at least version 6.5.0.
The 6.5.0 BETA is sufficient.

Once you have installed Couchbase, you will need to enable the travel-sample bucket.
You can do this from the Settings/Sample Buckets tab.

You also need to create a text search index, to allow the application to search for hotels.
In the Search tab, create an index for the travel-sample bucket named "hotels" with a type mapping for type "hotel".
Leave all other properties of the index at defaults. Wait for the "indexing progress" to reach 100%.

Then you need to enable the DP features, since the application will be working with collections.

```
couchbase-cli enable-developer-preview --enable -c http://localhost:8091 -u Administrator -p password
```

The tool `couchbase-cli` is located in
[the standard Couchbase installation directory](https://developer.couchbase.com/documentation/server/3.x/admin/Misc/install-location.html)
of your OS.

To download the repo, make a GOPATH directory and then use `go get` to fetch this repo.  From a terminal:

```bash
 go get -u "github.com/couchbaselabs/try-cb-golang"
 ```

Now change into the `try-cb-golang` directory.

Next, we need to set up the bucket, scope, and collections where the application will store its data.
Run the creation script from the `try-cb-golang` directory like this:

```
sh create-collections.sh
```

This script creates a bucket, a scope, and a collection with this structure:

* default (bucket)
  * larson-travel (scope)
    * users (collection)

Then start up the application.
 
```bash
 cd src/github.com/couchbaselabs/try-cb-golang/
 go run main.go
 ```

 Open a browser and load the url http://localhost:8080

## REST API DOCUMENTATION
The REST API for this example application can be found at:
[https://github.com/couchbaselabs/try-cb-frontend/blob/master/documentation/try-cb-api-spec-v2.adoc](https://github.com/couchbaselabs/try-cb-frontend/blob/master/documentation/try-cb-api-spec-v2.adoc)
