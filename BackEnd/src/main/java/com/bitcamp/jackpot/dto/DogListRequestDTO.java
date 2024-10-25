package com.bitcamp.jackpot.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DogListRequestDTO {
    int page;
    int size;
    String sort;
    String search;

    public Pageable getPageable() {
        String sort ="";
        switch (this.getSort()){
            case "name": sort += "name";break;
            case "recent": sort += "regDate"; break;
            case "heart": sort += "heart"; break;
        }

        return PageRequest.of(this.page -1, this.size, Sort.by(sort).descending());
    }
}
