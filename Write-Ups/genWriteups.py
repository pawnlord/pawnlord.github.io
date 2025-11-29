from markdown_it import MarkdownIt
import os

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

for name in posts:
    header += "<a href=\"" + name +".html\" id=\"button-link\" class=\"button-link-hover\">" + name + "</a></br>\n";

for name in posts:
    list += "<li><a href=\"" + name +".html\" id=\"button-link\" class=\"button-link-hover\">" + name + "</a></br>\n";

for name in posts:
    with open(name + ".md") as f:
        text = f.read()
    md = MarkdownIt()
    body = md.render(text)
    with open(name + ".html", "w") as f:
        f.write(template.format(name=name, replace_me_body=body, header=header))


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

fg.atom_file('atom.xml')
fg.rss_file('rss.xml')