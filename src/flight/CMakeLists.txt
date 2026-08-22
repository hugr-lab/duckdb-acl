# The Arrow Flight SQL door (specs/045). Everything Arrow-specific lives in this directory: the door
# will grow a session middleware, a ticket registry, the catalog RPCs and an ingest path, and none of
# that belongs next to the rewriter. It is also the part of the build that can be absent - only an
# ACL_FLIGHT=1 build compiles any of it - so keeping it behind one directory keeps that boundary
# visible rather than spread through the source list.
set(ACL_FLIGHT_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/acl_flight_door.cpp
    PARENT_SCOPE)
