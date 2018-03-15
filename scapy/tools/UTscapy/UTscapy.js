function make_visible(elt) {
    elt.style.visibility='visible';
    elt.style.position='relative';
}

function make_hidden(elt) {
    elt.style.visibility='hidden';
    elt.style.position='absolute';
}

function hide(id) {
    make_hidden(document.getElementById(id+'-'))
    make_visible(document.getElementById(id+'+'))
    make_hidden(document.getElementById(id))
}

function show(id) {
    make_visible(document.getElementById(id+'-'))
    make_hidden(document.getElementById(id+'+'))
    make_visible(document.getElementById(id))
}

function goto_id(id) {
    document.body.scrollTop = document.getElementById(id).offsetTop;
}

function passed(id) {
    return /passed/.test(document.getElementById(id).className)
}

function show_all(idbase) {
    try {
        for(i=0;;i++)  {
            show(idbase+i);
        }
    } catch (error) { }
}
function hide_all(idbase) {
    try {
        for(i=0;;i++)  {
            hide(idbase+i);
        }
    } catch (error) { }
}
function show_passed(idbase) {
    try {
        for(i=0;;i++)  {
            if (passed(idbase+i)) {
                show(idbase+i);
            }
        }
    } catch (error) { }
}

function show_failed(idbase) {
    try {
        for(i=0;;i++)  {
            if (! passed(idbase+i)) {
                show(idbase+i);
            }
        }
    } catch (error) { }
}

