include(FetchContent)

FetchContent_Declare(
    DocTest
    GIT_REPOSITORY https://github.com/doctest/doctest.git
    GIT_TAG v2.4.11
)

FetchContent_MakeAvailable(DocTest)
