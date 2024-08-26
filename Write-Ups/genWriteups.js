
let writeupNames = ["TCP1P", "Buckeye", "CursedCTF", "umdctf", "sekaiCTF"];





async function replaceInstances(name){
    var text = await (await fetch(name + ".md")).text();
    console.log(text)
    var converter = new showdown.Converter(),
        html      = converter.makeHtml(text);
        
    var replace = document.getElementById("content-replace-me");
    replace.innerHTML = html;
    console.log(html)
}

function replaceHeader() {
    var replace = document.getElementById("header-replace-me");
    var innerHTML = "<div id=\"header-list\">\n"; 
    for(var i in writeupNames) {
        var name = writeupNames[i];
        innerHTML += "<a href=\"" + name +".html\" id=\"button-link\" class=\"button-link-hover\">" + name + "</a></br>\n";
    }
    innerHTML += "</div>\n"
    console.log(innerHTML)
    replace.innerHTML = innerHTML;

}

function replaceList() {
    var replace = document.getElementById("list-replace-me");
    var innerHTML = "<ul id=\"content\">\n"; 
    for(var i in writeupNames) {
        var name = writeupNames[i];
        innerHTML += "<li><a href=\"" + name +".html\" id=\"button-link\" class=\"button-link-hover\">" + name + "</a></li>\n";
    }
    innerHTML += "</divul\n"
    console.log(innerHTML)
    replace.innerHTML = innerHTML;
}