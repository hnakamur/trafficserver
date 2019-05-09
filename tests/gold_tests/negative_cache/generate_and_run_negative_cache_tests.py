#!/usr/bin/env python
import copy
import subprocess
from jinja2 import Environment, FileSystemLoader

# test case combination patterns
#
# empty_response=True
#   -> 2 cases: allow_empty_doc=True, False
# empty_response=False
#   -> 1 case: allow_empty_doc=False
#
# negative_caching_enabled=False
#   -> 1 case: status_code is in default negative caching list or not
# negative_caching_enabled=True
#   -> 2 cases: status code is in list, or not in list

common_test_cases_per_status = [
    {
        'empty_response': False,
        'negative_caching_enabled': True, 'in_negative_caching_list': True,
        'gold_file_basenames': [ 'non_empty-cache_fill', 'non_empty-cache_hit', 'non_empty-cache_ram_hit' ]
    },
    {
        'empty_response': False,
        'negative_caching_enabled': True, 'in_negative_caching_list': False,
        'gold_file_basenames': [ 'non_empty-cache_fill', 'non_empty-cache_hit', 'non_empty-cache_ram_hit' ]
    },
    {
        'empty_response': False,
        'negative_caching_enabled': False,
        'gold_file_basenames': [ 'non_empty-cache_no_fill', 'non_empty-cache_no_fill', 'non_empty-cache_no_fill' ]
    },

    {
        'empty_response': True, 'allow_empty_doc': True,
        'negative_caching_enabled': True, 'in_negative_caching_list': True,
        'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_hit', 'empty-cache_ram_hit' ]
    },
    {
        'empty_response': True, 'allow_empty_doc': True,
        'negative_caching_enabled': True, 'in_negative_caching_list': False,
        'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_hit', 'empty-cache_ram_hit' ]
    },
    {
        'empty_response': True, 'allow_empty_doc': True,
        'negative_caching_enabled': False,
        'gold_file_basenames': [ 'empty-cache_no_fill', 'empty-cache_no_fill', 'empty-cache_no_fill' ]
    },

    {
        'empty_response': True, 'allow_empty_doc': False,
        'negative_caching_enabled': True, 'in_negative_caching_list': True,
        'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_fill', 'empty-cache_fill' ]
    },
    {
        'empty_response': True, 'allow_empty_doc': False,
        'negative_caching_enabled': True, 'in_negative_caching_list': False,
        'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_fill', 'empty-cache_fill' ]
    },
    {
        'empty_response': True, 'allow_empty_doc': False,
        'negative_caching_enabled': False,
        'gold_file_basenames': [ 'empty-cache_no_fill', 'empty-cache_no_fill', 'empty-cache_no_fill' ]
    },
]

common_test_cases_per_status_50x = [
    {
        'empty_response': False,
        'negative_caching_enabled': True, 'in_negative_caching_list': True,
        'gold_file_basenames': [ 'non_empty-cache_fill', 'non_empty-cache_hit-expires', 'non_empty-cache_ram_hit-expires' ]
    },
    {
        'empty_response': False,
        'negative_caching_enabled': True, 'in_negative_caching_list': False,
        'gold_file_basenames': [ 'non_empty-cache_fill', 'non_empty-cache_hit', 'non_empty-cache_ram_hit' ]
    },
    {
        'empty_response': False,
        'negative_caching_enabled': False,
        'gold_file_basenames': [ 'non_empty-cache_no_fill', 'non_empty-cache_no_fill', 'non_empty-cache_no_fill' ]
    },

    {
        'empty_response': True, 'allow_empty_doc': True,
        'negative_caching_enabled': True, 'in_negative_caching_list': True,
        'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_hit-expires', 'empty-cache_ram_hit-expires' ]
    },
    {
        'empty_response': True, 'allow_empty_doc': True,
        'negative_caching_enabled': True, 'in_negative_caching_list': False,
        'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_hit', 'empty-cache_ram_hit' ]
    },
    {
        'empty_response': True, 'allow_empty_doc': True,
        'negative_caching_enabled': False,
        'gold_file_basenames': [ 'empty-cache_no_fill', 'empty-cache_no_fill', 'empty-cache_no_fill' ]
    },

    {
        'empty_response': True, 'allow_empty_doc': False,
        'negative_caching_enabled': True, 'in_negative_caching_list': True,
        'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_fill', 'empty-cache_fill' ]
    },
    {
        'empty_response': True, 'allow_empty_doc': False,
        'negative_caching_enabled': True, 'in_negative_caching_list': False,
        'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_fill', 'empty-cache_fill' ]
    },
    {
        'empty_response': True, 'allow_empty_doc': False,
        'negative_caching_enabled': False,
        'gold_file_basenames': [ 'empty-cache_no_fill', 'empty-cache_no_fill', 'empty-cache_no_fill' ]
    },
]

test_cases = {
    '201': common_test_cases_per_status,
    '202': common_test_cases_per_status,
    '203': [
        {
            'empty_response': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'non_empty-cache_fill', 'non_empty-cache_hit', 'non_empty-cache_ram_hit' ]
        },
        {
            'empty_response': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'non_empty-cache_fill', 'non_empty-cache_hit', 'non_empty-cache_ram_hit' ]
        },
        {
            'empty_response': False,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'non_empty-cache_fill', 'non_empty-cache_hit', 'non_empty-cache_ram_hit' ]
        },

        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_hit', 'empty-cache_ram_hit' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_hit', 'empty-cache_ram_hit' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_hit', 'empty-cache_ram_hit' ]
        },

        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_fill', 'empty-cache_fill' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_fill', 'empty-cache_fill' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_fill', 'empty-cache_fill' ]
        },
    ],
    '204': [
        # NOTE: There must not be cases for empty_response=False since 204 is for No Content
        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ '204-cache_fill', '204-cache_hit', '204-cache_ram_hit' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ '204-cache_fill', '204-cache_fill', '204-cache_fill' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ '204-cache_no_fill', '204-cache_no_fill', '204-cache_no_fill' ]
        },

        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ '204-cache_fill', '204-cache_hit', '204-cache_ram_hit' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ '204-cache_fill', '204-cache_fill', '204-cache_fill' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ '204-cache_no_fill', '204-cache_no_fill', '204-cache_no_fill' ]
        },
    ],
    '205': common_test_cases_per_status,

     # NOTE: Status 206 Partial Content must be tested separately with special treatment for range requests.

    '207': common_test_cases_per_status,
    '208': common_test_cases_per_status,
    '226': common_test_cases_per_status,

    '300': [
        {
            'empty_response': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'non_empty-cache_fill', 'non_empty-cache_hit', 'non_empty-cache_ram_hit' ]
        },
        {
            'empty_response': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'non_empty-cache_fill', 'non_empty-cache_hit', 'non_empty-cache_ram_hit' ]
        },
        {
            'empty_response': False,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'non_empty-cache_fill', 'non_empty-cache_hit', 'non_empty-cache_ram_hit' ]
        },

        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_hit', 'empty-cache_ram_hit' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_hit', 'empty-cache_ram_hit' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_hit', 'empty-cache_ram_hit' ]
        },

        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_fill', 'empty-cache_fill' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_fill', 'empty-cache_fill' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_fill', 'empty-cache_fill' ]
        },
    ],

    '301': [
        {
            'empty_response': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'non_empty-cache_fill', 'non_empty-cache_hit', 'non_empty-cache_ram_hit' ]
        },
        {
            'empty_response': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'non_empty-cache_fill', 'non_empty-cache_hit', 'non_empty-cache_ram_hit' ]
        },
        {
            'empty_response': False,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'non_empty-cache_fill', 'non_empty-cache_hit', 'non_empty-cache_ram_hit' ]
        },

        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_hit', 'empty-cache_ram_hit' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_hit', 'empty-cache_ram_hit' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_hit', 'empty-cache_ram_hit' ]
        },

        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_fill', 'empty-cache_fill' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_fill', 'empty-cache_fill' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'empty-cache_fill', 'empty-cache_fill', 'empty-cache_fill' ]
        },
    ],

    '302': [
        {
            'empty_response': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'non_empty-cache_no_fill', 'non_empty-cache_no_fill', 'non_empty-cache_no_fill' ]
        },
        {
            'empty_response': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'non_empty-cache_no_fill', 'non_empty-cache_no_fill', 'non_empty-cache_no_fill' ]
        },
        {
            'empty_response': False,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'non_empty-cache_no_fill', 'non_empty-cache_no_fill', 'non_empty-cache_no_fill' ]
        },

        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'empty-cache_no_fill', 'empty-cache_no_fill', 'empty-cache_no_fill' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'empty-cache_no_fill', 'empty-cache_no_fill', 'empty-cache_no_fill' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'empty-cache_no_fill', 'empty-cache_no_fill', 'empty-cache_no_fill' ]
        },

        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'empty-cache_no_fill', 'empty-cache_no_fill', 'empty-cache_no_fill' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'empty-cache_no_fill', 'empty-cache_no_fill', 'empty-cache_no_fill' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'empty-cache_no_fill', 'empty-cache_no_fill', 'empty-cache_no_fill' ]
        },
    ],
    '303': [
        {
            'empty_response': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'non_empty-cache_no_fill', 'non_empty-cache_no_fill', 'non_empty-cache_no_fill' ]
        },
        {
            'empty_response': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'non_empty-cache_no_fill', 'non_empty-cache_no_fill', 'non_empty-cache_no_fill' ]
        },
        {
            'empty_response': False,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'non_empty-cache_no_fill', 'non_empty-cache_no_fill', 'non_empty-cache_no_fill' ]
        },

        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'empty-cache_no_fill', 'empty-cache_no_fill', 'empty-cache_no_fill' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'empty-cache_no_fill', 'empty-cache_no_fill', 'empty-cache_no_fill' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'empty-cache_no_fill', 'empty-cache_no_fill', 'empty-cache_no_fill' ]
        },

        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'empty-cache_no_fill', 'empty-cache_no_fill', 'empty-cache_no_fill' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'empty-cache_no_fill', 'empty-cache_no_fill', 'empty-cache_no_fill' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'empty-cache_no_fill', 'empty-cache_no_fill', 'empty-cache_no_fill' ]
        },
    ],

     # NOTE: Status 304 Not Modified must be tested separately with special treatment.

    '305': common_test_cases_per_status,
    '403': common_test_cases_per_status,
    '404': common_test_cases_per_status,
    '405': common_test_cases_per_status,
    '414': common_test_cases_per_status,
    '415': common_test_cases_per_status,

     # NOTE: Status 416 Requested Range Not Satisfiable must be tested separately with special treatment for range requests.

    '417': common_test_cases_per_status,
    '418': common_test_cases_per_status,
    '421': common_test_cases_per_status,
    '422': common_test_cases_per_status,
    '423': common_test_cases_per_status,
    '424': common_test_cases_per_status,
    '425': common_test_cases_per_status,
    '426': common_test_cases_per_status,
    '428': common_test_cases_per_status,
    '429': common_test_cases_per_status,
    '431': common_test_cases_per_status,
    '451': common_test_cases_per_status,

    '500': [
        {
            'empty_response': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'non_empty-cache_fill-no_date', 'non_empty-cache_hit-no_date-expires', 'non_empty-cache_ram_hit-no_date-expires' ]
        },
        {
            'empty_response': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'non_empty-cache_fill-no_date', 'non_empty-cache_hit-no_date', 'non_empty-cache_ram_hit-no_date' ]
        },
        {
            'empty_response': False,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'non_empty-cache_no_fill-no_date', 'non_empty-cache_no_fill-no_date', 'non_empty-cache_no_fill-no_date' ]
        },

        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'empty-cache_fill-no_date', 'empty-cache_hit-no_date-expires', 'empty-cache_ram_hit-no_date-expires' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'empty-cache_fill-no_date', 'empty-cache_hit-no_date', 'empty-cache_ram_hit-no_date' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': True,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'empty-cache_no_fill-no_date', 'empty-cache_no_fill-no_date', 'empty-cache_no_fill-no_date' ]
        },

        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': True,
            'gold_file_basenames': [ 'empty-cache_fill-no_date', 'empty-cache_fill-no_date', 'empty-cache_fill-no_date' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': True, 'in_negative_caching_list': False,
            'gold_file_basenames': [ 'empty-cache_fill-no_date', 'empty-cache_fill-no_date', 'empty-cache_fill-no_date' ]
        },
        {
            'empty_response': True, 'allow_empty_doc': False,
            'negative_caching_enabled': False,
            'gold_file_basenames': [ 'empty-cache_no_fill-no_date', 'empty-cache_no_fill-no_date', 'empty-cache_no_fill-no_date' ]
        },
    ],

    '501': common_test_cases_per_status_50x,
    '502': common_test_cases_per_status_50x,
    '503': common_test_cases_per_status_50x,
    '504': common_test_cases_per_status_50x,

     # NOTE: Status 505 HTTP Version Not Supported must be tested separately with special treatment.

    '506': common_test_cases_per_status_50x,
    '507': common_test_cases_per_status_50x,
    '508': common_test_cases_per_status_50x,
    '510': common_test_cases_per_status_50x,
    '511': common_test_cases_per_status_50x,
}

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
status_texts = {
    "100": "Continue",
    "101": "Switching Protocol",
    "102": "Processing",
    "103": "Early Hints",
    "200": "OK",
    "201": "Created",
    "202": "Accepted",
    "203": "Non-Authoritative Information",
    "204": "No Content",
    "205": "Reset Content",
    "206": "Partial Content",
    "207": "Multi-Status",
    "208": "Multi-Status",
    "226": "IM Used",
    "300": "Multiple Choice",
    "301": "Moved Permanently",
    "302": "Found",
    "303": "See Other",
    "304": "Not Modified",
    "305": "Use Proxy",
    "306": "unused",
    "307": "Temporary Redirect",
    "308": "Permanent Redirect",
    "400": "Bad Request",
    "401": "Unauthorized",
    "402": "Payment Required",
    "403": "Forbidden",
    "404": "Not Found",
    "405": "Method Not Allowed",
    "406": "Not Acceptable",
    "407": "Proxy Authentication Required",
    "408": "Request Timeout",
    "409": "Conflict",
    "410": "Gone",
    "411": "Length Required",
    "412": "Precondition Failed",
    "413": "Payload Too Large",
    "414": "URI Too Long",
    "415": "Unsupported Media Type",
    "416": "Requested Range Not Satisfiable",
    "417": "Expectation Failed",
    "418": "I'm a teapot",
    "421": "Misdirected Request",
    "422": "Unprocessable Entity",
    "423": "Locked",
    "424": "Failed Dependency",
    "425": "Too Early",
    "426": "Upgrade Required",
    "428": "Precondition Required",
    "429": "Too Many Requests",
    "431": "Request Header Fields Too Large",
    "451": "Unavailable For Legal Reasons",
    "500": "Internal Server Error",
    "501": "Not Implemented",
    "502": "Bad Gateway",
    "503": "Service Unavailable",
    "504": "Gateway Timeout",
    "505": "HTTP Version Not Supported",
    "506": "Variant Also Negotiates",
    "507": "Insufficient Storage",
    "508": "Loop Detected",
    "510": "Not Extended",
    "511": "Network Authentication Required",
}

negative_caching_list_default = "204,305,403,404,405,414,500,501,502,503,504"

env = Environment(loader=FileSystemLoader('templates'))

def build_config(env, status_code, test_case):
    config = copy.copy(test_case)
    config['status_code'] = status_code

    if config['empty_response']:
        config['response_body'] = ''
        if config['status_code'] == '204':
            config['response_content_length_line'] = ''
        else:
            config['response_content_length_line'] = r'Content-Length: 0\r\n'
        config['config_allow_empty_doc'] = 1 if config['allow_empty_doc'] else 0
    else:
        config['response_body'] = 'yyy'
        config['response_content_length_line'] = r'Content-Length: 3\r\n'
        config['config_allow_empty_doc'] = 0

    config['config_negative_caching_enabled'] = 1 if config['negative_caching_enabled'] else 0
    if config['negative_caching_enabled']:
        if config['in_negative_caching_list']:
            config['config_negative_caching_list'] = config['status_code']
        else:
            config['config_negative_caching_list'] = '599'
        config['status_in_list'] = config['in_negative_caching_list']
    else:
        config['c_negative_caching_list'] = ''
        config['status_in_list'] = config['status_code'] in negative_caching_list_default.split(",")
    config['response_connection_value'] = 'close'
    #config['response_connection_value'] = 'keep-alive'

    config['test_summary'] = env.get_template("test_summary.j2").render(config)
    config['test_name'] = env.get_template('test_name.j2').render(config)
    return config

def build_configs(env, test_cases):
    configs = []
    for status_code, cases_per_status_code in test_cases.items():
        for test_case in cases_per_status_code:
            config = build_config(env, status_code, test_case)
            configs.append(config)
    return configs

def write_testcases_summary_text():
    max_widths = [0, 0, 0, 0]
    rows = []
    for config in build_configs(env, test_cases):
        row = [config['test_name']] + config['gold_file_basenames']
        for i in range(len(max_widths)):
            max_widths[i] = max(max_widths[i], len(row[i]))
        rows.append(row)

    format = '{{0[0]:<{0[0]}}} {{0[1]:<{0[1]}}} {{0[2]:<{0[2]}}} {{0[3]}}\n'.format(max_widths)
    with open('negative_cache_test_summary.txt', 'w') as file:
        file.write(format.format(['test_name', 'gold1', 'gold2', 'gold3']))
        for row in rows:
            file.write(format.format(row))

def write_testcases_summary_csv():
    import csv
    with open('negative_cache_test_summary.csv', 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile, delimiter=',',
                               quotechar='"', quoting=csv.QUOTE_MINIMAL)
        csvwriter.writerow(['test_name', 'gold1', 'gold2', 'gold3'])
        for config in build_configs(env, test_cases):
            csvwriter.writerow([config['test_name']] + config['gold_file_basenames'])

def generate_test_scripts():
    for config in build_configs(env, test_cases):
        test_py_filename = config['test_name'] + '.test.py'
        print(env.get_template('test.py.j2').render(config), file=open(test_py_filename, 'w'))

def run_tests():
    test_names = []
    for config in build_configs(env, test_cases):
        test_names.append(config['test_name'])
    subprocess.run(['autest', '--autest-site', '../autest-site', '--ats-bin', '/usr/local/bin', '-D', '.', '-f', ','.join(test_names)])

if __name__ == '__main__':
    write_testcases_summary_text()
    write_testcases_summary_csv()
    generate_test_scripts()
    run_tests()
