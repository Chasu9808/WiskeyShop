async function uploadToServer (formObj) {
    console.log("formObj" + formObj)

    const response = await axios({
        method: 'post',
        url : '/upload',
        data : formObj,
        headers : {
            // 오타 주의 , 이름과 값이 정해짐.
            'Content-Type' : 'multipart/form-data',
        }
    });
    return response.data
}

async function uploadProfileToServer (formObj) {
    console.log("formObj 확인" + formObj)

    const response = await axios({
        method: 'post',
        url : '/uploadProfile',
        data : formObj,
        headers : {
            // 오타 주의 , 이름과 값이 정해짐.
            'Content-Type' : 'multipart/form-data',
        }
    });
    return response.data
}

async function removeFileToServer(uuid,fileName) {
    const response = await axios.delete(`/delete/${uuid}_${fileName}`)
    return response.data
}
