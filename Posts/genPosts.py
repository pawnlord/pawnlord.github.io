from markdown_it import MarkdownIt
import os
import subprocess
import datetime

from feedgen.feed import FeedGenerator

(dirpath, _dirnames, filenames) = next(os.walk("."))

with open("page_template.html") as f:
    template = f.read()

posts = []

for file in filenames:
    if file.endswith(".md"):
        name = file.removesuffix(".md")
        posts.append(name)

header = ""
list = ""

def formatDate(month, day, year):
    months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]

    return months[int(month) - 1] + ", " + day + ", " + year

def getDatePosted(filename):
    p = subprocess.run(["git", "log", "--reverse", "--pretty=\"format:%cs\"", filename], capture_output=True)
    dates = p.stdout.splitlines()
    if len(dates) < 1:
        return "Unpublished"
    (year, month, day) = dates[0].decode().removeprefix('"format:').removesuffix('"').split('-')
    return formatDate(month, day, year) 

def getTimestampPosted(filename):
    p = subprocess.run(["git", "log", "--reverse", "--pretty=\"format:%ci\"", filename], capture_output=True)
    dates = p.stdout.splitlines()
    if len(dates) < 1:
        return None
    return dates[0].decode().removeprefix('"format:').removesuffix('"')


for name in posts:
    header += "<a href=\"" + name +".html\" id=\"button-link\" class=\"button-link-hover\">" + name + "</a></br>\n";

for name in posts:
    list += "<li><a href=\"" + name +".html\" id=\"button-link\" class=\"button-link-hover\">" + name + "</a></br>\n";

for name in posts:
    date = getDatePosted(name + ".md")
    post_header = f"<p>Posted {date}</p><hr>\n{header}" 
    with open(name + ".md") as f:
        text = f.read()
    md = MarkdownIt()
    body = md.render(text)
    with open(name + ".html", "w") as f:
        f.write(template.format(name=name, replace_me_body=body, header=post_header))


index = """
<h1> Write-Ups: </h1>
<h2> Capture The Flags: </h2>
<ul id="content">
{list}
</ul>
			
<c>see also:</c><br />
&emsp;<a href="../Projects/index.html" id="link" class="link-hover">Projects</a><br />
&emsp;<a href="https://github.com/pawnlord" id="link" class="link-hover">My Github</a><br />
"""

index = index.format(list=list)

with open("index.html", "w") as f:
    f.write(template.format(name="Index", replace_me_body=index, header=header))

# Now we create the feed
fg = FeedGenerator()
fg.id('https://pawnlord.github.io/Write-Ups/index.html')
fg.title('Write-Ups Feed')
fg.author( {'name':'pawnlord','email':'randlopq@gmail.com'} )
fg.subtitle('A feed of write-ups created for CTFs')
fg.language('en')
fg.link(href='https://pawnlord.github.io/Write-Ups/atom.xml', rel="self", type="application/rss+xml")

for name in posts:
    fe = fg.add_entry()
    link = "https://pawnlord.github.io/Write-Ups/" + name + ".html"
    fe.id(link.replace(" ", "%20"))
    fe.title(name + ' write-ups')
    fe.link(href=link.replace(" ", "%20"))
    date = getTimestampPosted(name + ".md")
    if date == None:
        fe.pubDate("1970-01-01T00:00:00.000Z")
    else:
        fe.pubDate(date)

fg.atom_file('atom.xml')
fg.rss_file('rss.xml')