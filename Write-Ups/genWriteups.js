import * as prism from "/prism.js"

let writeupNames = ["TCP1P", "Buckeye", "CursedCTF", "umdctf", "sekaiCTF"];

export async function replaceInstances(name){
    var text = await (await fetch(name + ".md")).text();
    var converter = new showdown.Converter(),
        html      = converter.makeHtml(text);
        
    var replace = document.getElementById("content-replace-me");
    replace.innerHTML = html;
    Prism.highlightAll();
}

export function replaceHeader() {
    var replace = document.getElementById("header-replace-me");
    var innerHTML = "<div id=\"header-list\">\n"; 
    for(var i in writeupNames) {
        var name = writeupNames[i];
        innerHTML += "<a href=\"" + name +".html\" id=\"button-link\" class=\"button-link-hover\">" + name + "</a></br>\n";
    }
    innerHTML += "</div>\n"
    replace.innerHTML = innerHTML;

}

export function replaceList() {
    var replace = document.getElementById("list-replace-me");
    var innerHTML = "<ul id=\"content\">\n"; 
    for(var i in writeupNames) {
        var name = writeupNames[i];
        innerHTML += "<li><a href=\"" + name +".html\" id=\"button-link\" class=\"button-link-hover\">" + name + "</a></li>\n";
    }
    innerHTML += "</divul\n"
    replace.innerHTML = innerHTML;
}