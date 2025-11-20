import scrapy, sqlite3, socket, requests, re
from bs4 import BeautifulSoup

def write_to_domain_database(name):
    conn = sqlite3.connect("ScrapyDataBase", isolation_level=None)
    conn.execute('CREATE TABLE IF NOT EXISTS Domains ("url" TEXT NOT NULL)')
    print(" Checking for " + name + " in database")
    entry_exists = conn.execute("SELECT DISTINCT url FROM Domains WHERE url='{}'".format(name))
    db_result = str(entry_exists.fetchall()).replace("[('","").replace("',)]","")
    # print("DB_RESULT:::   " + db_result)
    if db_result == name:
        print("\n" + name + " is already in DB")
        return
    else:
        sql = """INSERT INTO Domains (url)
                                VALUES ('{}');""".format(name)
        conn.execute(sql)
        print("\n" + name + " saved to database")
        return

def write_to_info_database(name, ip, content_type, x_frame_opts,
                           x_xss_prot, server, x_cont_type,
                           referrer_policy, access_control_allow_origin):
    print("Attempting to write to Info Database")
    conn = sqlite3.connect("ScrapyDataBase", isolation_level=None)

    entry_exists = conn.execute("SELECT DISTINCT url FROM Info WHERE url='{}'".format(name))
    db_result = str(entry_exists.fetchall()).replace("[('", "").replace("',)]", "")
    if db_result == name:
        print("\n" + name + " is already in DB")
        return
    else:
        conn.execute('''CREATE TABLE IF NOT EXISTS Info ("url" TEXT NOT NULL,
                                                        "ip_address" TEXT NOT NULL,
                                                        "content_type" TEXT,
                                                        "x_frame_options" TEXT,
                                                        "x_xss_protection" TEXT,
                                                        "server" TEXT,
                                                        "x_content_type_options" TEXT,
                                                        "referrer_policy" TEXT,
                                                        "access_control_allow_origin" TEXT)''')
        # print("DB_RESULT:::   " + db_result)
        sql = """INSERT INTO Info (url, ip_address, content_type, x_frame_options, 
                               x_xss_protection, server, x_content_type_options,
                               referrer_policy, access_control_allow_origin)
                                VALUES ('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}');""".format(name, ip, content_type, x_frame_opts,
                                                                     x_xss_prot, server, x_cont_type, referrer_policy,
                                                                     access_control_allow_origin)
        conn.execute(sql)
        print("\n" + name + " saved to database")
        return


def sanitize_url(url):
    sanitized = ""
    if url.startswith("https://") and url.endswith("/"):
        sanitized = url.replace("https://", "")
        sanitized = sanitized[:-1]
    elif url.startswith("http://") and url.endswith("/"):
        sanitized = url.replace("https://", "")
        sanitized = sanitized[:-1]
    elif url.startswith("https://"):
        sanitized = url.replace("https://", "")
    elif url.startswith("http://"):
        sanitized = url.replace("http://", "")
    return sanitized


def get_server_info(domain_name):
    print("\nGetting server info")
    header_response = requests.head(domain_name)
    ip = ""
    content_type = ""
    x_frame_options = ""
    x_xss_protection = ""
    server = ""
    x_content_type_options = ""
    referrer_policy = ""
    access_control_allow_origin = ""

    try:
        server = header_response.headers['server']
        content_type = header_response.headers['Content-Type']
        x_frame_options = header_response.headers['X-Frame-Options']
        x_xss_protection = header_response.headers['X-XSS-Protection']
        x_content_type_options = header_response.headers['X-Content-Type-Options']
        referrer_policy = header_response.headers['Referrer=Policy']
        access_control_allow_origin = header_response.headers['Access-Control-Allow-Origin']

    except KeyError as err:
        print(err)

    ip = socket.gethostbyname(sanitize_url(domain_name))

    # write_to_domain_database(str(domain_name), ip, server, content_type, title)
    if len(ip) > 0:
        print("IP Address::  " + ip)
        print("Server::  " + server)
        print("Content_Type::  " + content_type)
        print("X-Frame-Options::  " + x_frame_options)
        print("X-XSS-Protection::  " + x_xss_protection)
        print("X-Content-Type-Options::  " + x_content_type_options)
        print("Referrer-Policy::  " + referrer_policy)
        print("Access-Control-Allow-Origin::  " + access_control_allow_origin)
        write_to_info_database(domain_name, ip, content_type, x_frame_options, x_xss_protection,
                               server, x_content_type_options, referrer_policy,
                               access_control_allow_origin)
    else:
        print("NO IP")


class FastCrawlSpider(scrapy.Spider):
    name = "FastCrawl" # identifies spider, must be unique within project

    async def start(self):
        urls = ["https://www.example.com"]
        for url in urls:
            print("URL IN URLS LOOP")
            yield scrapy.Request(url=url, callback=self.parse)

    def parse(self, response):
        links = response.css("a::attr(href)").getall()
        tld_list = (".com/", ".gov/", ".net/", ".edu/", ".org/",
                    ".io/", ".co.uk/", ".ie/", ".info/", ".me/",
                    ".in", ".info/", ".fr/", ".de/")
        for link in links:
            if link.startswith("https://www.linkedin.com/jobs/"):
                return
            else:
                next_page = response.urljoin(link)
                write_to_domain_database(next_page)
                # email_scraper(response)
                if next_page.endswith(tld_list):
                    get_server_info(next_page)
                yield scrapy.Request(next_page, callback=self.parse)

