
# create bucket
curl -X POST -u Administrator:password http://localhost:8091/pools/default/buckets -d name=default -d ramQuotaMB=100

# create scope
curl -u Administrator:password -X POST http://localhost:8091/pools/default/buckets/default/collections -d name=scope-travel

# create collections in each scope
curl -u Administrator:password -X POST http://localhost:8091/pools/default/buckets/default/collections/scope-travel -d name=users

# show what we have made
echo '\n\n\n\nTHE FINAL RESULT'
curl -u Administrator:password -X GET http://localhost:8091/pools/default/buckets/default/collections
echo '\n'
