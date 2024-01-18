# Importing required libraries
import re
from collections import Counter
from urllib.parse import urlparse
import tldextract


class UrlFeatureExtractor:
    def __init__(self):
        # Initializing variables
        self.unparsed_url = None
        self.parsed_url = None
        self.hostname = None
        self.words_hostname = None
        self.domain = None
        self.tld = None
        self.subdomains = None
        self.path = None
        self.path_segments = None

        # Initialize variables with data
        self.all_brands = self._read_txt_file("./txt/all_brands.txt")
        self.phish_hints = self._read_txt_file("./txt/phish_hints.txt")
        self.sho_srvcs = self._read_txt_file("./txt/sho_srvcs.txt")
        self.sus_tlds = self._read_txt_file("./txt/sus_tlds.txt")
        self.tld_list = self._read_txt_file("./txt/tld_list.txt")
        self.mal_path_ext = self._read_txt_file("./txt/mal_path_ext.txt")

    # * == Public Functions == #
    def set_url(self, new_value):
        url_domain = tldextract.extract(new_value)
        subdomains = url_domain.subdomain.split(".")
        subdomains.reverse()

        self.unparsed_url = new_value
        self.parsed_url = urlparse(new_value)
        self.hostname = self.parsed_url.hostname
        self.words_hostname = self.hostname.split(".")
        self.domain = url_domain.domain
        self.tld = url_domain.suffix
        self.subdomains = subdomains
        self.path = self.parsed_url.path
        self.path_segments = self.path.split("/")

    def get_domain(self):
        return self.domain

    def get_url_features(self):
        length_url = self._calculate_length_url()
        length_hostname = self._calculate_length_hostname()

        has_ip = self._if_has_ip()

        nb_dots = self._count_dots()
        nb_hyphens = self._count_hyphens()
        nb_at = self._count_ats()
        nb_qm = self._count_question_marks()
        nb_and = self._count_ands()
        nb_eq = self._count_equals()
        nb_underscore = self._count_underscores()
        nb_tilde = self._count_tildes()
        nb_percent = self._count_percents()
        nb_asterisk = self._count_asterisks()
        nb_colon = self._count_colons()
        nb_comma = self._count_commas()
        nb_semicolon = self._count_semicolons()
        nb_dollar = self._count_dollars()
        nb_space = self._count_spaces()

        nb_www = self._count_wwws()
        nb_com = self._count_coms()
        nb_dslash = self._count_dslashes()
        http_in_path = self._count_protocol_path()

        https_token = self._using_https()

        ratio_digits_url = self._calculate_ratio_digits_url()
        ratio_digits_host = self._calculate_ratio_digits_host()

        punycode = self._has_punycode()

        port = self._has_port()

        tld_in_path = self._has_tld_in_path()
        tld_in_subdomain = self._has_tld_in_subdomains()

        abnormal_subdomain = self._has_abnormal_subdomain()

        nb_subdomains = self._count_subdomains()

        prefix_suffix = self._check_hyphen()

        shortening_service = self._check_shortening_service()

        path_extension = self._check_malicious_extension()

        length_words_raw = self._count_words_in_url()
        char_repeat = self._count_characters_repeat()
        shortest_words_raw = self._shortest_word_in_url()
        shortest_word_host = self._shortest_word_in_hostname()
        shortest_word_path = self._shortest_word_in_path()
        longest_words_raw = self._longest_word_in_url()
        longest_word_host = self._longest_word_in_hostname()
        longest_word_path = self._longest_word_in_path()
        avg_words_raw = self._calculate_average_word_length()
        avg_word_host = self._calculate_average_word_host()
        avg_word_path = self._calculate_average_word_path()

        phish_hints = self._count_phish_hints()

        domain_in_brand = self._has_brand_in_domain()
        brand_in_subdomain = self._has_brand_in_subdomain()
        brand_in_path = self._has_brand_in_path()

        suspicious_tld = self._check_tld()

        url_features = [
            length_url,
            length_hostname,
            has_ip,
            nb_dots,
            nb_hyphens,
            nb_at,
            nb_qm,
            nb_and,
            nb_eq,
            nb_underscore,
            nb_tilde,
            nb_percent,
            nb_asterisk,
            nb_colon,
            nb_comma,
            nb_semicolon,
            nb_dollar,
            nb_space,
            nb_www,
            nb_com,
            nb_dslash,
            http_in_path,
            https_token,
            ratio_digits_url,
            ratio_digits_host,
            punycode,
            port,
            tld_in_path,
            tld_in_subdomain,
            abnormal_subdomain,
            nb_subdomains,
            prefix_suffix,
            shortening_service,
            path_extension,
            length_words_raw,
            char_repeat,
            shortest_words_raw,
            shortest_word_host,
            shortest_word_path,
            longest_words_raw,
            longest_word_host,
            longest_word_path,
            avg_words_raw,
            avg_word_host,
            avg_word_path,
            phish_hints,
            domain_in_brand,
            brand_in_subdomain,
            brand_in_path,
            suspicious_tld,
        ]

        return url_features

    # * == Private Functions == #

    # Assigning the txt lines to a variable
    def _read_txt_file(self, file_path):
        with open(file_path, "r") as file:
            return [line.strip() for line in file.readlines()]

    # * === URL Lengths === #

    def _calculate_length_url(self):
        return len(self.unparsed_url)

    def _calculate_length_hostname(self):
        return len(self.hostname)

    # * === IP Address === #

    def _if_has_ip(self):
        # Regular expression pattern to match both IPv4 and IPv6 addresses
        ip_pattern = (
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        )

        # Used re.search to find the IP address in the URL
        match = re.search(ip_pattern, self.unparsed_url)

        if match:
            return 1
        else:
            return 0

    # * === Special Characters === #

    def _count_dots(self):
        dot_count = self.unparsed_url.count(".")

        return dot_count

    def _count_hyphens(self):
        hyphen_count = self.unparsed_url.count("-")

        return hyphen_count

    def _count_ats(self):
        at_count = self.unparsed_url.count("@")

        return at_count

    def _count_question_marks(self):
        question_mark_count = self.unparsed_url.count("?")

        return question_mark_count

    def _count_ands(self):
        and_count = self.unparsed_url.count("&")

        return and_count

    def _count_equals(self):
        equal_count = self.unparsed_url.count("=")

        return equal_count

    def _count_underscores(self):
        underscore_count = self.unparsed_url.count("_")

        return underscore_count

    def _count_tildes(self):
        tilde_count = self.unparsed_url.count("~")

        return tilde_count

    def _count_percents(self):
        percent_count = self.unparsed_url.count("%")

        return percent_count

    def _count_asterisks(self):
        asterisk_count = self.unparsed_url.count("*")

        return asterisk_count

    def _count_colons(self):
        colon_count = self.unparsed_url.count(":")

        return colon_count

    def _count_commas(self):
        comma_count = self.unparsed_url.count(",")

        return comma_count

    def _count_semicolons(self):
        semicolon_count = self.unparsed_url.count(";")

        return semicolon_count

    def _count_dollars(self):
        dollar_count = self.unparsed_url.count("$")

        return dollar_count

    def _count_spaces(self):
        space_count_1 = self.unparsed_url.count("%20")
        space_count_2 = self.unparsed_url.count(" ")
        total_count = space_count_1 + space_count_2

        return total_count

    # * === Common Terms === #

    def _count_wwws(self):
        www_count = self.unparsed_url.count("www")

        return www_count

    def _count_coms(self):
        com_count = self.unparsed_url.count(".com")

        return com_count

    def _count_dslashes(self):
        dslash_count = self.unparsed_url.count("//")

        return dslash_count

    def _count_protocol_path(self):
        http_count = self.path.count("http")
        https_count = self.path.count("https")
        total_count = http_count + https_count

        return total_count

    # * === HTTPS Token === #

    def _using_https(self):
        if self.unparsed_url.startswith("https://"):
            return 0
        else:
            return 1

    # * === Ratio Digits === #

    def _calculate_ratio_digits(self, text):
        digit_count = sum(1 for char in text if char.isdigit())
        total_characters = len(text)
        ratio = digit_count / total_characters if total_characters > 0 else 0.0
        return ratio

    def _calculate_ratio_digits_url(self):
        return self._calculate_ratio_digits(self.unparsed_url)

    def _calculate_ratio_digits_host(self):
        return self._calculate_ratio_digits(self.hostname)

    # * === Punycode === #

    def _has_punycode(self):
        # Regular expression pattern to match punycode-encoded domain names
        punycode_pattern = r"xn--[a-zA-Z0-9]+"
        match = re.search(punycode_pattern, self.unparsed_url)

        if match:
            return 1
        else:
            return 0

    # * === Port === #

    def _has_port(self):
        match = bool(self.parsed_url.port)

        if match:
            return 1
        else:
            return 0

    # * === TLD Position === #

    def _has_tld_in_path(self):
        for segment in self.path_segments:
            if segment.lower() in self.tld_list:
                return 1

        return 0

    def _has_tld_in_subdomains(self):
        result = (
            1 if any(subdomain in self.tld_list for subdomain in self.subdomains) else 0
        )

        return result

    # * === Abnormal Subdomains === #

    def _has_abnormal_subdomain(self):
        # A regular expression pattern for the abnormal subdomain
        pattern = r"^w[w]?[0-9]*?$"

        result = (
            1
            if any(re.match(pattern, subdomain) for subdomain in self.subdomains)
            else 0
        )

        return result

    # * === Subdomains === #

    def _count_subdomains(self):
        num_subdomains = len(self.subdomains)

        return num_subdomains

    # * === Prefix Suffix === #

    def _check_hyphen(self):
        # Check if "-" is present in the domain
        result = 1 if "-" in self.domain else 0

        return result

    # * === Shortening Service === #

    def _check_shortening_service(self):
        result = 1 if self.domain in self.sho_srvcs else 0

        return result

    # * === Path Extension === #

    def _check_malicious_extension(self):
        result = (
            1
            if any(
                segment.endswith(tuple(self.mal_path_ext))
                for segment in self.path_segments
            )
            else 0
        )

        return result

    # * === NLP Features === #

    def _count_words_in_url(self):
        url_path = self.parsed_url.path
        query = self.parsed_url.query

        path_words = url_path.split("/")
        query_words = query.split("&") if query else []

        all_words = path_words + query_words
        # Filter out empty strings
        all_words = [word for word in all_words if word]

        num_words = len(all_words)

        return num_words

    def _count_characters_repeat(self):
        cleaned_url = "".join(char for char in self.unparsed_url if char.isalnum())
        char_count = Counter(cleaned_url)

        most_common = char_count.most_common(1)

        return most_common[0][1]

    def _shortest_word_in_url(self):
        # Calculate the length of each URL component
        scheme_length = len(self.parsed_url.scheme)
        netloc_length = len(self.parsed_url.netloc)
        path_length = len(self.parsed_url.path)
        query_length = len(self.parsed_url.query)
        fragment_length = len(self.parsed_url.fragment)

        min_length = min(
            scheme_length, netloc_length, path_length, query_length, fragment_length
        )

        return min_length

    def _shortest_word_in_hostname(self):
        shortest_length = min(len(word) for word in self.words_hostname)

        return shortest_length

    def _shortest_word_in_path(self):
        words = re.findall(r"\w+", self.unparsed_url)

        shortest_word_path = min(len(word) for word in words)

        return shortest_word_path

    def _longest_word_in_url(self):
        # Calculate the length of each URL component
        scheme_length = len(self.parsed_url.scheme)
        netloc_length = len(self.parsed_url.netloc)
        path_length = len(self.parsed_url.path)
        query_length = len(self.parsed_url.query)
        fragment_length = len(self.parsed_url.fragment)

        max_length = max(
            scheme_length, netloc_length, path_length, query_length, fragment_length
        )

        return max_length

    def _longest_word_in_hostname(self):
        longest_length_hostname = max(len(word) for word in self.words_hostname)

        return longest_length_hostname

    def _longest_word_in_path(self):
        words = re.findall(r"\w+", self.unparsed_url)

        # Find the length of the shortest word
        longest_word_path = max(len(word) for word in words)

        return longest_word_path

    def _calculate_average_word_length(self):
        url_parts = (
            [self.parsed_url.scheme]
            + list(self.parsed_url.netloc.split("."))
            + self.parsed_url.path.split("/")
        )

        words = [word for part in url_parts for word in part.split("-") if word]

        if words:
            total_length = sum(len(word) for word in words)
            average_length = total_length / len(words)
        else:
            average_length = 0

        return average_length

    def _calculate_average_word_host(self):
        if self.words_hostname:
            total_length = sum(len(word) for word in self.words_hostname)
            average_length = total_length / len(self.words_hostname)
        else:
            average_length = 0

        return average_length

    def _calculate_average_word_path(self):
        words = [word for word in self.path.split("/") if word]

        if words:
            total_length = sum(len(word) for word in words)
            average_length = total_length / len(words)
        else:
            average_length = 0

        return average_length

    # * === Phish Hints === #

    def _count_phish_hints(self):
        # Extract the full URL as a string
        full_url = str(self.unparsed_url)

        # Count the total number of occurrences of the phish hints
        total_occurrences = sum(
            full_url.lower().count(word.lower()) for word in self.phish_hints
        )

        return total_occurrences

    # * === Brand Domains === #

    def _has_brand_in_domain(self):
        result = 0 if self.domain in self.all_brands else 1
        return result

    def _has_brand_in_subdomain(self):
        result = (
            1
            if any(subdomain in self.all_brands for subdomain in self.subdomains)
            else 0
        )
        return result

    def _has_brand_in_path(self):
        result = 1 if any(path in self.all_brands for path in self.path_segments) else 0
        return result

    # * === Suspicious TLD === #

    def _check_tld(self):
        result = 1 if self.tld in self.sus_tlds else 0

        return result
