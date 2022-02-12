#include <iostream>
#include <string>

// clang++ libbpf_example.cc .output/libbpf.a -I.output -lelf -lz -o
// libbpf_example

extern "C" {
#include <bpf/libbpf.h>
#include <sys/resource.h>
}

void setLimit() {
  struct rlimit limit = {};
  limit.rlim_cur = RLIM_INFINITY;
  limit.rlim_max = RLIM_INFINITY;

  if (setrlimit(RLIMIT_MEMLOCK, &limit)) {
    // TODO: Add log to record error.
    throw std::runtime_error("Error with setting limited locked memory.");
  }
}

void unpinBpfMap(bpf_object *obj) {
  bpf_object__load(obj);
  bpf_map *map;

  bpf_map__for_each(map, obj) {
    std::string map_path("/sys/fs/bpf/" +
                         static_cast<std::string>(bpf_map__name(map)));
    bpf_map__unpin(map, map_path.c_str());
  }
  bpf_object__close(obj);
}

void printBpfObjectInfo(bpf_object *obj) {
  bpf_object__load(obj);
  std::cout << std::endl << "load bpf object" << std::endl << std::endl;
  std::cout << std::endl
            << "Object name: "
            << static_cast<std::string>(bpf_object__name(obj)) << std::endl
            << std::endl;

  bpf_program *prog;
  bpf_object__for_each_program(prog, obj) {
    std::cout << bpf_program__name(prog) << " --> "
              << bpf_program__section_name(prog) << std::endl;

    bpf_link *lnk;
    lnk = bpf_program__attach(prog);
    std::cout << "first attach " << libbpf_get_error(lnk) << std::endl;

    auto err = bpf_link__destroy(lnk);
    std::cout << "detach error code = " << err << std::endl;
  }

  bpf_map *map;
  bpf_map__for_each(map, obj) {
    std::string map_name(bpf_map__name(map));
    std::string map_path("/sys/fs/bpf/" + map_name);

    std::cout << "Map name: " << bpf_map__name(map) << " : " << bpf_map__fd(map)
              << std::endl;
  }
  bpf_object__close(obj);
  std::cout << std::endl << "close bpf object" << std::endl << std::endl;
}

int main() {
  setLimit();

  std::string path0("not_exist.cc");
  std::string path1("libbpf_example.cc");
  std::string path2("/bpf_not_exist");
  std::string path3("bootstrap.bpf.o");

  bpf_object *obj0 = bpf_object__open(path0.c_str());
  const int err0 = libbpf_get_error(obj0);
  std::cout << "err0 = " << err0 << std::endl;

  bpf_object *obj1 = bpf_object__open(path1.c_str());
  const int err1 = libbpf_get_error(obj1);
  std::cout << "err1 = " << err1 << std::endl;

  bpf_object *obj2 = bpf_object__open(path2.c_str());
  const int err2 = libbpf_get_error(obj2);
  std::cout << "err2 = " << err2 << std::endl;

  bpf_object *obj3 = bpf_object__open(path3.c_str());
  const int err3 = libbpf_get_error(obj3);
  std::cout << "err3 = " << err3 << std::endl;
  if (!err3) {
    printBpfObjectInfo(obj3);
    // unpinBpfMap(obj3);
  }
}
