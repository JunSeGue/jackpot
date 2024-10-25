import React from "react";
import styled from "styled-components";

const Container = styled.div`
  display: flex;
  flex-direction: column;
  justify-content: center;
  max-height: 400px;
  width: 100%;
  margin: 0;
`;

const BoxWrapper = styled.div`
  width: 100%;
  border-top: 1px solid black;
  border-bottom: 1px solid black;
  padding: 10px 0;
`;

const Title = styled.h2`
  width: 100%;
  text-align: left;
  margin: 0;
  padding: 0;
`;

const VideoWrapper = styled.div`
  display: flex;
  margin-top: 20px;
  width: 80%;
  height: 300px;
  align-self: center;
  position: relative;
`;

const VideoIframe = styled.iframe`
  width: 100%;
  height: 100%;
  border: none;
`;

const YouTubeContainer = ({ youtubeLink }) => {
  return (
    <Container>
      <BoxWrapper>
        <Title>관련 유튜브 영상</Title>
      </BoxWrapper>
      <VideoWrapper>
        <VideoIframe
          src={youtubeLink}
          title="YouTube video player"
          allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
          referrerPolicy="strict-origin-when-cross-origin"
          allowFullScreen
        />
      </VideoWrapper>
    </Container>
  );
};

export default YouTubeContainer;
