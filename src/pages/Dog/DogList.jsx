import Dog from "../../dogList/Dog";
import React, { useEffect, useState } from "react";

import { Box, Container } from "@mui/material";

// import MOCKDATA from "./MockData";
import SortSelector from "../../dogList/SortSelector";
import PageComponent from "../../dogList/PageComponent";
import apiClient from "../../token/AxiosConfig";
import styled from "styled-components";
import image from "../../static/fundingBanner.jpg";

const DogListPage = () => {
  const [dogsData, setDogsData] = useState([]);
  const [pageInfo, setPageInfo] = useState({
    sort: "recent",
    page: 1,
    size: 9,
  });
  const [totalPages, setTotalPages] = useState();

  useEffect(() => {
    dogListAPI(pageInfo);
  }, [pageInfo]);

  const handleSortChange = (e, newSort) => {
    e.preventDefault();
    if (newSort !== null) {
      setPageInfo((prevInfo) => ({
        ...prevInfo,
        sort: newSort,
        page: 1,
      }));
    }
  };

  const handlePageChange = (page) => {
    setPageInfo((prevInfo) => ({
      ...prevInfo,
      page,
    }));
  };

  const dogListAPI = async () => {
    try {
      const response = await apiClient.get("dog/dogList", {
        params: pageInfo,
      });
      console.log(response.data);

      setDogsData(response.data);

      setTotalPages(Math.ceil(response.data.totalDogNum / pageInfo.size));

      setDogsData(response.data.dogList);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="container flex flex-column align-center ">
      <StyledImageBox className=" section-Image flex">
        <img src={image} alt="대표 사진 " style={{ width: "1200px" }} />
      </StyledImageBox>

      <Container disableGutters>
        <SortSelector value={pageInfo.sort} onChange={handleSortChange} />
        <div className="section-doglist">
          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: "repeat(3,1fr)",
              gap: 8,
              padding: "20px",
            }}
          >
            {dogsData.map((dog) => (
              <Box key={dog.dogId}>
                <Dog dog={dog} onHeartToggle={dogListAPI} />
              </Box>
            ))}
          </Box>
        </div>
      </Container>
      <PageComponent
        pageInfo={pageInfo}
        totalPages={totalPages}
        onPageChange={handlePageChange}
        onPrev={() => handlePageChange(Math.max(pageInfo.page - 1, 1))}
        onNext={() => handlePageChange(Math.min(pageInfo.page + 1, totalPages))}
      />
    </div>
  );
};

const StyledImageBox = styled.div`
  margin: 0;

  width: fit-content;
  max-width: 1400px;
  img {
    width: 100%;
  }
`;

export default DogListPage;
