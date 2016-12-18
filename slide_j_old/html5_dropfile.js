
function setDropOneFileToElementID(id, oneFileCallbackFunc) {
    $(function() {
        var droppable = $("#" + id);

	// 1. check File API is available
	if(!window.FileReader) {
	    return false;
	}

	// 2. assign canceling event
	var cancelEvent = function(event) {
	    event.preventDefault();
	    event.stopPropagation();
	    return false;
	}
 
	droppable.bind("dradenter", cancelEvent);
	droppable.bind("dragover", cancelEvent);
 
	// 3. set drop event handler for one file
	var handleDroppedFile = function(event) {
	    // 3.1. process only first file
	    var file = event.originalEvent.dataTransfer.files[0];
	
	    // 3.2. read file
	    var fileReader = new FileReader();
	    fileReader.onload = function(event) {
		oneFileCallbackFunc(file.name, event.target.result);
	    }
	    fileReader.readAsText(file);
	
	    // cancel default process
	    cancelEvent(event);
	    return false;
	}
 
	droppable.bind("drop", handleDroppedFile);
    });
};
