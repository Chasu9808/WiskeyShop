//axios 통신 테스트용 함수
async function getTest(bno) {
    const result = await axios.get(`/replies/list/${bno}`)
    // console.log("result 확인 : " + result)
    // 데이터 확인용
    // return result.data
    return result
}
//댓글 목록 출력하는 함수.
// bno: 현재 게시글 번호
// page: 페이지번호
// size: 페이지당 출력 갯수
// goLast: 마지막에 최신 댓글이 있다면, 마지막 댓글로 가는 여부.
async function getList({bno,page,size,goLast}){
   const result = await axios.get(`/replies/list/${bno}`,{params : {page,size}})

    // 마지막 댓글 보러가기
    if(goLast) {
        const total = result.data.total
        const lastPage = parseInt(Math.ceil(total/size))
        return getList({bno:bno, page:lastPage, size:size})
    }

    return result.data
}

//댓글 등록, 모달창으로 작업하기.
async function addReply(replyObj){
   const response = await axios.post(`/replies/`,replyObj)
    return response.data
}

// 조회
async function getReply(rno){
    const response = await axios.get(`/replies/${rno}`)
    return response.data
}

// 수정
async function updateReply(replyObj){
    console.log("replyObj 확인: " + replyObj.rno)
    console.log("replyObj 확인2: " + replyObj.replyText)
    const response = await axios.put(`/replies/${replyObj.rno}`,replyObj)
    return response.data
}

// 삭제
async function deleteReply(rno){

    const response = await axios.delete(`/replies/${rno}`)
    return response.data
}





