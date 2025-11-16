package com.busanit501.boot501.dto.upload;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UploadResultDTO {

    private String uuid;
    private String fileName;
    private boolean imgCheck;

    // uuid+"_"+fileName , 만들어주는 메서드
    public String getLink() {
        if(imgCheck) {
            return "s_"+uuid+"_"+fileName;
        } else {
            return uuid+"_"+fileName;
        }
    }

}
