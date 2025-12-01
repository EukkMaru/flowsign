
if (STATIC_CODECS)
    set (PLUGIN_LIST
        cd_eth.cc
        cd_linux_sll.cc
        cd_raw.cc
    )

else (STATIC_CODECS)
    add_dynamic_module (cd_eth codecs cd_eth.cc)
    add_dynamic_module (cd_linux_sll codecs cd_linux_sll.cc)
    add_dynamic_module (cd_raw codecs cd_raw.cc)

endif (STATIC_CODECS)


if (STATIC_CODECS)
    add_library(root_codecs OBJECT
        ${PLUGIN_LIST}
    )
endif (STATIC_CODECS)
