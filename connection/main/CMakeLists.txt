idf_component_register(SRCS "server.cpp"
                    INCLUDE_DIRS "."
                    EMBED_TXTFILES srv.crt
                    EMBED_TXTFILES srv.key
                    EMBED_TXTFILES ca.crt
)
