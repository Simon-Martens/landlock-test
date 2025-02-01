/*
 * Orioginally a sample file fom the linux kernet source tree. Located under
 * samples/landlock/sandboxer.c with the following coyright notice:
 *
 * SPDX-License-Identifier: GPL-2.0h
 * Copyright © 2017-2020 Mickaël Salaün
 * <mic@digikod.net> Copyright © 2020 ANSSI
 *
 * This file has been modified to be used as a standalone program.
 * The same License terms as the original file apply.
 * Copyright © 2024 Simon Martens
 */

#define _GNU_SOURCE
#define __SANE_USERSPACE_TYPES__
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>

#include "landlock_fallback.h"

//////////////////////////////////////////// CONSTS
#define ENV_FS_RO_NAME "LL_FS_RO"
#define ENV_FS_RW_NAME "LL_FS_RW"
#define ENV_TCP_BIND_NAME "LL_TCP_BIND"
#define ENV_TCP_CONNECT_NAME "LL_TCP_CONNECT"
#define ENV_DELIMITER ":"
#define LANDLOCK_ABI_LAST 4

/////////////////////////////////////////// BITMASKS
/* clang-format off */
#define ACCESS_FS_ROUGHLY_READ ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_READ_DIR)

#define ACCESS_FS_ROUGHLY_WRITE ( \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_REMOVE_DIR | \
	LANDLOCK_ACCESS_FS_REMOVE_FILE | \
	LANDLOCK_ACCESS_FS_MAKE_CHAR | \
	LANDLOCK_ACCESS_FS_MAKE_DIR | \
	LANDLOCK_ACCESS_FS_MAKE_REG | \
	LANDLOCK_ACCESS_FS_MAKE_SOCK | \
	LANDLOCK_ACCESS_FS_MAKE_FIFO | \
	LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
	LANDLOCK_ACCESS_FS_MAKE_SYM | \
	LANDLOCK_ACCESS_FS_REFER | \
	LANDLOCK_ACCESS_FS_TRUNCATE)

// INFO: these only apply to files
#define ACCESS_FILE ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_TRUNCATE)
/* clang-format on */

static int parse_path(char *env_path, const char ***const path_list) {
  int i, num_paths = 0;

  if (env_path) {
    num_paths++;
    for (i = 0; env_path[i]; i++) {
      if (env_path[i] == ENV_DELIMITER[0])
        num_paths++;
    }
  }
  *path_list = malloc(num_paths * sizeof(**path_list));
  for (i = 0; i < num_paths; i++)
    (*path_list)[i] = strsep(&env_path, ENV_DELIMITER);

  return num_paths;
}

static int populate_ruleset_fs(const char *const env_var, const int ruleset_fd,
                               const __u64 allowed_access) {
  int num_paths, i, ret = 1;
  char *env_path_name;
  const char **path_list = NULL;

  // INFO: This is a kernel struct defined in landlock.h
  // It contains access rights bitmask & a file descriptor.
  struct landlock_path_beneath_attr path_beneath = {
      .parent_fd = -1,
  };

  env_path_name = getenv(env_var);
  if (!env_path_name) {
    // INFO: not setting the env is an error
    fprintf(stderr, "Missing environment variable %s\n", env_var);
    return 1;
  }

  // INFO: getenv returns a pointer to the environment variable, so we need to
  // copy here
  env_path_name = strdup(env_path_name);
  if (!env_path_name) {
    fprintf(stderr, "Could not allocate memory for %s\n", env_var);
    return 1;
  }

  // WARNING: this unsets the env after using, probably to prevent the
  // program from being able to read the paths after the ruleset is read.
  unsetenv(env_var);

  num_paths = parse_path(env_path_name, &path_list);
  if (num_paths == 1 && path_list[0][0] == '\0') {
    // INFO: we just return if the ruleset is empty. It's not an error.
    // Then, no access to anything is permitted.
    ret = 0;
    goto out_free_name;
  }

  for (i = 0; i < num_paths; i++) {
    struct stat statbuf;

    path_beneath.parent_fd = open(path_list[i], O_PATH | O_CLOEXEC);
    if (path_beneath.parent_fd < 0) {
      // INFO: then again this fails if a single path doesn't exist
      // The open syscall with O_PATH needs x persmissions on the whole path to
      // traverse the directory. We should abort on ENOENT, but maybe not on
      // EACCES, since an access would be denied anyway; landlock permissions
      // set or not.
      fprintf(stderr, "Failed to open \"%s\": %s\n", path_list[i],
              strerror(errno));
      goto out_free_name;
    }
    if (fstat(path_beneath.parent_fd, &statbuf)) {
      close(path_beneath.parent_fd);
      goto out_free_name;
    }
    path_beneath.allowed_access = allowed_access;

    // INFO: Only set flags related to files if the path is a file, everything
    // else is set to 0. &= sets the bytes to 1 that are set in both bitmasks.
    if (!S_ISDIR(statbuf.st_mode))
      path_beneath.allowed_access &= ACCESS_FILE;
    if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath,
                          0)) {
      fprintf(stderr, "Failed to update the ruleset with \"%s\": %s\n",
              path_list[i], strerror(errno));
      close(path_beneath.parent_fd);
      goto out_free_name;
    }
    close(path_beneath.parent_fd);
  }
  ret = 0;

out_free_name:
  free(path_list);
  free(env_path_name);
  return ret;
}

static int populate_ruleset_net(const char *const env_var, const int ruleset_fd,
                                const __u64 allowed_access) {
  int ret = 1;
  char *env_port_name, *strport;
  struct landlock_net_port_attr net_port = {
      .allowed_access = allowed_access,
      .port = 0,
  };

  env_port_name = getenv(env_var);
  if (!env_port_name)
    return 0;
  env_port_name = strdup(env_port_name);
  unsetenv(env_var);

  while ((strport = strsep(&env_port_name, ENV_DELIMITER))) {
    net_port.port = atoi(strport);
    if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &net_port, 0)) {
      fprintf(stderr, "Failed to update the ruleset with port \"%llu\": %s\n",
              net_port.port, strerror(errno));
      goto out_free_name;
    }
  }
  ret = 0;

out_free_name:
  free(env_port_name);
  return ret;
}

// Function to check Landlock compatibility and adjust ruleset attributes
int configure_landlock(struct landlock_ruleset_attr *ruleset_attr) {
  // INFO: passing NULL means just checking if the kernel supports the desired
  // landlock API
  int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
  if (abi <= 0) {
    const int err = errno;
    perror("Failed to check Landlock compatibility");
    switch (err) {
    case ENOSYS:
      fprintf(stderr, "Hint: Landlock is not supported by the current kernel. "
                      "To support it, build the kernel with "
                      "CONFIG_SECURITY_LANDLOCK=y and prepend "
                      "\"landlock,\" to the content of CONFIG_LSM.\n");
      break;
    case EOPNOTSUPP:
      fprintf(stderr, "Hint: Landlock is currently disabled. "
                      "It can be enabled in the kernel configuration by "
                      "prepending \"landlock,\" to the content of CONFIG_LSM, "
                      "or at boot time by setting the same content to the "
                      "\"lsm\" kernel parameter.\n");
      break;
    }
    return -1;
  }

  /* Best-effort security. */
  switch (abi) {
  case 1:
    // Removes LANDLOCK_ACCESS_FS_REFER for ABI < 2
    ruleset_attr->handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
    fprintf(stderr,
            "Hint: You should update the running kernel "
            "to leverage Landlock features "
            "provided by ABI version %d (instead of %d).\n",
            LANDLOCK_ABI_LAST, abi);
    __attribute__((fallthrough));
  case 2:
    // Removes LANDLOCK_ACCESS_FS_TRUNCATE for ABI < 3
    ruleset_attr->handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
    fprintf(stderr,
            "Hint: You should update the running kernel "
            "to leverage Landlock features "
            "provided by ABI version %d (instead of %d).\n",
            LANDLOCK_ABI_LAST, abi);
    __attribute__((fallthrough));
  case 3:
    // Removes network support for ABI < 4
    ruleset_attr->handled_access_net &=
        ~(LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP);
    fprintf(stderr,
            "Hint: You should update the running kernel "
            "to leverage Landlock features "
            "provided by ABI version %d (instead of %d).\n",
            LANDLOCK_ABI_LAST, abi);
    __attribute__((fallthrough));
  case LANDLOCK_ABI_LAST:
    break;
  default:
    fprintf(stderr,
            "Hint: You should check for updates of sandboxer "
            "to possibly leverage Landlock features "
            "provided by ABI version %d (instead of %d).\n",
            abi, LANDLOCK_ABI_LAST);
  }

  return abi;
}

int main(const int argc, char *const argv[], char *const *const envp) {
  const char *cmd_path;
  char *const *cmd_argv;
  int ruleset_fd;
  char *env_port_name;
  __u64 access_fs_ro = ACCESS_FS_ROUGHLY_READ,
        access_fs_rw = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE;

  // INFO: Check if the command provided is valid
  if (argc < 2) {
    fprintf(stderr,
            "usage: %s=\"...\" %s=\"...\" %s=\"...\" %s=\"...\"%s "
            "<cmd> [args]...\n\n",
            ENV_FS_RO_NAME, ENV_FS_RW_NAME, ENV_TCP_BIND_NAME,
            ENV_TCP_CONNECT_NAME, argv[0]);
    fprintf(stderr, "Launch a command in a restricted environment.\n\n");
    fprintf(stderr, "Environment variables containing paths and ports each "
                    "separated by a colon:\n");
    fprintf(stderr,
            "* %s: list of paths allowed to be used in a read-only way.\n",
            ENV_FS_RO_NAME);
    fprintf(stderr,
            "* %s: list of paths allowed to be used in a read-write way.\n\n",
            ENV_FS_RW_NAME);
    fprintf(stderr, "Environment variables containing ports are optional "
                    "and could be skipped.\n");
    fprintf(stderr, "* %s: list of ports allowed to bind (server).\n",
            ENV_TCP_BIND_NAME);
    fprintf(stderr, "* %s: list of ports allowed to connect (client).\n",
            ENV_TCP_CONNECT_NAME);
    fprintf(stderr,
            "\nexample:\n"
            "%s=\"/bin:/lib:/usr:/proc:/etc:/dev/urandom\" "
            "%s=\"/dev/null:/dev/full:/dev/zero:/dev/pts:/tmp\" "
            "%s=\"9418\" "
            "%s=\"80:443\" "
            "%s bash -i\n\n",
            ENV_FS_RO_NAME, ENV_FS_RW_NAME, ENV_TCP_BIND_NAME,
            ENV_TCP_CONNECT_NAME, argv[0]);
    fprintf(stderr,
            "This sandboxer can use Landlock features "
            "up to ABI version %d.\n",
            LANDLOCK_ABI_LAST);
    return 1;
  }

  // INFO: This is a kernel struct defined in landlock.h
  // We later pass this to landlock_create_ruleset to get a ruleset fd
  // descriptor. We need to adjust the bitmasks to the features (different
  // restrictions on fs or net) we wish to handle.
  struct landlock_ruleset_attr ruleset_attr = {
      .handled_access_fs = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE,
      .handled_access_net =
          LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
  };

  configure_landlock(&ruleset_attr);

  access_fs_ro &= ruleset_attr.handled_access_fs;
  access_fs_rw &= ruleset_attr.handled_access_fs;

  // INFO: Network restrictions are optional
  env_port_name = getenv(ENV_TCP_BIND_NAME);
  if (!env_port_name) {
    ruleset_attr.handled_access_net &= ~LANDLOCK_ACCESS_NET_BIND_TCP;
  }
  env_port_name = getenv(ENV_TCP_CONNECT_NAME);
  if (!env_port_name) {
    ruleset_attr.handled_access_net &= ~LANDLOCK_ACCESS_NET_CONNECT_TCP;
  }

  // INFO: Syscall to create a new ruleset. The returning fd is used to
  // append rules to the ruleset.
  // LANDLOCK_ACCESS_FS_REFER: this right is always denied, even if it's
  // not declared as handled in the ruleset passed to the kernel below.
  // Landlock will always deny reparenting of of files between different
  // directories. Moving files aor linking files to a directory with wider
  // access rights is always denied.
  ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
  if (ruleset_fd < 0) {
    perror("Failed to create a ruleset");
    return 1;
  }

  if (populate_ruleset_fs(ENV_FS_RO_NAME, ruleset_fd, access_fs_ro)) {
    goto err_close_ruleset;
  }
  if (populate_ruleset_fs(ENV_FS_RW_NAME, ruleset_fd, access_fs_rw)) {
    goto err_close_ruleset;
  }

  if (populate_ruleset_net(ENV_TCP_BIND_NAME, ruleset_fd,
                           LANDLOCK_ACCESS_NET_BIND_TCP)) {
    goto err_close_ruleset;
  }
  if (populate_ruleset_net(ENV_TCP_CONNECT_NAME, ruleset_fd,
                           LANDLOCK_ACCESS_NET_CONNECT_TCP)) {
    goto err_close_ruleset;
  }

  // INFO: we try to prevent the process from gaining privs (eg. with SUID) in
  // the future. PR_SET_NO_NEW_PRIVS is required to be set before
  // landlock_restrict_self
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("Failed to restrict privileges");
    goto err_close_ruleset;
  }
  if (landlock_restrict_self(ruleset_fd, 0)) {
    perror("Failed to enforce ruleset");
    goto err_close_ruleset;
  }
  close(ruleset_fd);

  // INFO: The challenge of this program is that access to the called
  // executables and shared libraries can't be restricted.
  // We could
  // - always retain read access to /lib /bin /usr and /etc
  // - always retain write access to /tmp, /proc
  // - retain read & write access to CWD.
  // INFO: it's not easy to auto-detect neccessary paths for an executable. We
  // could:
  // - always retain read access to the $PATH directories OR
  // - try to get the PATH of the desired process with `which`
  // - try to keep default profiles for different executables
  cmd_path = argv[1];
  cmd_argv = argv + 1;
  execvpe(cmd_path, cmd_argv, envp);

  // INFO: This code is unreachable if execvpe is successful
  // So the programm errs out if it reaches this point.
  fprintf(stderr, "Failed to execute \"%s\": %s\n", cmd_path, strerror(errno));
  fprintf(stderr, "Hint: access to the binary, the interpreter or "
                  "shared libraries may be denied.\n");
  return 1;

err_close_ruleset:
  close(ruleset_fd);
  return 1;
}
