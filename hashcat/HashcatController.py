from .Modes import HashMode, AttackMode
import logging
import os
import subprocess
import sys


class HashcatController(object):
    """
    Control hashcat from python. This object is meant to represent the hashcat
    binary. Hashcat can be run multiple times from one HashcatController.
    """

    def __init__(
            self,
            binary="/usr/bin/hashcat",
            log_to_console=False,
            logs_dir=None
    ):
        """Initialize the controller object."""
        self.logs_dir = logs_dir
        self.logger = self._setup_logger(logs_dir, log_to_console)
        self.logger.debug("Initializing HashcatController")

        if not os.access(binary, os.X_OK):
            self.loggger.error(f"{binary} is not an executable file")
            raise Exception(f"{binary} is not an executable file")
        self.bin = binary
        self.logger.debug(f"Using hahscat at {self.bin}")
        version = subprocess.check_output([self.bin, "--version"])
        self.version = version.decode().strip()
        self.logger.debug(f"hashcat {self.version}")

        self.benchmarks = {}
        self.logger.debug("No benchmarks run")

        self.arguments = {}
        self.hashlist = None
        self.wordlist = None
        self.mask = None

        self._command = []
        self.proc = None
        self.logger.debug("Done initializing HashcatController")

    def _setup_logger(self, logs_dir, log_to_console):
        """
        Setup logging. This includes a directory to store the logs and results
        produced by the controller. If the the directory already exists, throw
        an error. And logging directly to the console if desired.

        Return the logger object for the controller to use
        """
        log_format_str = "%(asctime)s"
        log_format_str += " | %(name)s"
        log_format_str += " | %(levelname)s"
        log_format_str += " | %(filename)s:%(funcName)s::%(message)s"
        log_format = logging.Formatter(log_format_str)

        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        if log_to_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(log_format)
            logger.addHandler(console_handler)

        def _create_logs_dir(logs_dir, modifier=None):
            full_name = logs_dir
            if modifier is not None:
                full_name += f"_{modifier}"
            try:
                os.mkdir(full_name)
            except FileExistsError:
                if modifier is None:
                    modifier = 1
                else:
                    modifier += 1
                name = _create_logs_dir(logs_dir, modifier)
                return name

            # If everything is sucessful, return the final directory name
            return full_name

        if logs_dir:
            self.logs_dir = _create_logs_dir(logs_dir)
            file_handler = logging.FileHandler(
                f"{self.logs_dir}/controller.log"
            )
            file_handler.setFormatter(log_format)
            logger.addHandler(file_handler)

        logger.propogate = False

        if log_to_console:
            logger.info("Logger setup to log to console")
        if logs_dir:
            logger.info(f"Logger setup to store logs in {self.logs_dir}")


        return logger

    def benchmark(self, mode):
        """
        Run a benchmark for the specific hash mode given. Save the hashes
        per second found by the benchmark to the benchmarks dict. Return that
        value as well.
        """

        mode = HashMode.resolve_mode(mode)
        output = subprocess.check_output(
            [self.bin, f"-m{mode.value}", "--benchmark", "--machine-readable"]
        )
        results = output.decode().strip().split("\n")[2].split(":")
        hashes_per_second = results[5]
        self.benchmarks[mode] = hashes_per_second
        self.logger.debug(f"Benchmark for {mode.name}, {hashes_per_second}")
        return hashes_per_second

    def set_hashlist(self, hashlist):
        """Set the path to the hashlist that should be cracked."""

        if not os.access(hashlist, os.R_OK):
            error_msg = f"{hashlist} is not an readable file"
            self.logger.error(error_msg)
            raise Exception(error_msg)

        self.hashlist = hashlist
        self.logger.debug(f"Hashlist set to {hashlist}")

    def set_attack(self, mode, **kwargs):
        """
        Set the attack mode, useful with hashcat.Modes.AttackMode but an
        integer can be passed as the mode.

        Each attack requires different key word arguments to be preset:
          * (0) Straight: wordlist
          * (1) Combination: TODO
          * (3) Brute Force: mask
          * (6) Hybrid Wordlist + Mask: TODO
          * (7) Hybrid Mask + Wordlist: TODO
          * (9) Association: TODO
        """

        """
        if type(mode) == int:
            mode = AttackMode(mode)
        if type(mode) != AttackMode:
            error = "Attack mode must be set to AttackMode or int,"
            error += f" got {type(mode)}"
            raise TypeError(error)
        """
        mode = AttackMode.resolve_mode(mode)

        # Straight (Wordlist) Attack
        if mode == AttackMode.straight:
            wordlist = kwargs.get("wordlist")
            if not wordlist:
                error_msg = f"'wordlist' arg is required for strait attack"
                self.logger.error(error_msg)
                raise Exception(error_msg)
            if not os.access(wordlist, os.R_OK):
                error_msg = f"{wordlist} is not an readable file"
                self.logger.error(error_msg)
                raise Exception(error_msg)
            self.wordlist = wordlist
            self.logger.debug(f"Attack Mode set to '{mode}'")
            self.logger.debug(f"Straing Attack Wordlist set to '{wordlist}'")

        # Brute Force (Mask) Attack
        elif mode == AttackMode.brute_force:
            mask = kwargs.get("mask")
            if not mask:
                error_msg = "'mask' arg is required for brue forece attack"
                self.logger.error(error_msg)
                raise Exception(error_msg)

            self.mask = mask
            self.logger.debug(f"Attack Mode set to '{mode}'")
            self.logger.debug(f"Brute Force Mask set to '{mask}'")

        else:
            error_msg = f"{mode} has not been implimented yet"
            self.logger.error(error_msg)
            raise Exception(error_msg)

        self.arguments["--attack-mode"] = mode.value

    def set_hash_type(self, mode):
        """
        Set the hash type/mode, useful with hashcat.Modes.HashType but an
        integer can be passes as the mode
        """
        if type(mode) == HashMode:
            mode = mode.value
        if type(mode) != int:
            error = "Hash type must be set to HashMode or int,"
            error += f" got {type(mode)}"
            self.logger.error(error)
            raise TypeError(error)

        self.logger.debug(f"Hash Mode set to '{mode}'")
        self.arguments["--hash-type"] = mode

    def add_argument(self, arg, value=None):
        """
        Add an argument that will get added to the command. These will get
        added directly to the command line (for now) so include any leading
        dashes. If value is left at None, it will be assumed that the argument
        does not take any values
        """

        arg_exceptions = {
            "set_attack": ["-a", "--attack-mode"],
            "set_hash_type": ["-m", "--hash-type"],
        }
        for method, args in arg_exceptions.items():
            if arg in args:
                err = f"Don't use `add_argument` for {arg}, use {method}"
                self.logger.error(err)
                raise Exception(err)

        self.arguments[arg] = value

    def get_command(self):
        """Return the command that would be run right now"""
        self._generate_command()
        return self._command

    def _generate_command(self):
        """
        Take all of the options present and fill the command variable with an
        array that can be passed to Popen
        """
        # Verify all necessary arguments are here
        """
          * Attack Mode
          * Hash type
          * Hashlist
          * Wordlist or Mask
        """

        if not ("--attack-mode" in self.arguments.keys()):
            msg = "Attack mode has not been set, use set_attack"
            self.logger.error(msg)
            raise Exception(msg)
        if not ("--hash-type" in self.arguments.keys()):
            msg = "Hash type has not been set, use set_hash_type"
            self.logger.error(msg)
            raise Exception(msg)
        if self.hashlist is None:
            msg = "Hashlist has not been set, use set_hashlist"
            self.logger.error(msg)
            raise Exception(msg)

        command = [self.bin]
        command += [
            f"{arg}{f'={val}' if val is not None else ''}"
            for arg, val in self.arguments.items()
        ]
        command += [self.hashlist]

        # Set final argument based on Attack Type
        attack_mode = self.arguments["--attack-mode"]
        if attack_mode == AttackMode.straight.value:
            if self.wordlist is None:
                msg = "Wordlist has not been set, use set_wordlist"
                self.logger.error(msg)
                raise Exception(msg)
            command += [self.wordlist]

        elif attack_mode == AttackMode.brute_force.value:
            if self.mask is None:
                msg = "Mask has not been set, use set_mask"
                self.logger.error(msg)
                raise Exception(msg)
            command += [self.mask]

        # General checkall until other attack types are implimented
        else:
            msg = f"attack mode {AttackMode(attack_mode)} is not implimented yet"
            self.logger.error(msg)
            raise Exception(msg)
        self.logger.debug(f"Command generated successfully, '{command}'")
        self._command = command

    def run(self):
        """
        After everything has been set up properly, actually start a hashcat
        process. Return the pid of the process.
        """

        self._generate_command()
        self.proc = subprocess.Popen(
            self._command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        self.logger.debug(f"Command run, pid = {self.proc.pid}")
        return self.proc.pid

    def wait(self, timeout=None):
        """
        After a hashcat session has started, wait for it to finish. Timeout
        after timeout seconds. Return the return code, stdout, and stderr.
        """

        if self.proc is None:
            msg = "No hashcat process was started"
            self.logger.error(msg)
            raise Exception(msg)

        return_code = self.proc.wait(timeout)
        return return_code, self.proc.stdout, self.proc.stderr

    def show(self):
        """
        Run hashcat with the `--show` command to get any cracked hashes from
        the pot file. Return any cracked hashes in an array.
        """

        self._generate_command()
        self.logger.debug("Adding '--show' to run 'show' command")
        output = subprocess.check_output(self._command + ["--show"])
        return output.decode().split()

    def left(self):
        """
        Run hashcat with the `--left` command to get any uncracked hashes from
        the pot file. Return any uncracked hashes in an array.
        """

        self._generate_command()
        self.logger.debug("Adding '--left' to run 'left' command")
        output = subprocess.check_output(self._command + ["--left"])
        return output.decode().split()
