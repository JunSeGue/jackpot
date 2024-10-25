import React from "react";
import styled from "styled-components";

const DogButton = () => {
    const addButton = () => {
        window.location.href = "/admin/dogaddform";
    }
    return (
        <StyledWrapper>
            <button onClick={addButton}>
        <span>
          <svg
              height="24"
              width="24"
              viewBox="0 0 24 24"
              xmlns="http://www.w3.org/2000/svg"
          >
            <path d="M0 0h24v24H0z" fill="none"/>
            <path d="M11 11V5h2v6h6v2h-6v6h-2v-6H5v-2z" fill="currentColor"/>
          </svg>
          등록
        </span>
            </button>
        </StyledWrapper>
    );
};

const StyledWrapper = styled.div`
  button {
    border: 2px solid #24b4fb;
    background-color: #24b4fb;
    border-radius: 0.9em;
    cursor: pointer;
    padding: 0.8em 1.2em 0.8em 1em;
    transition: all ease-in-out 0.2s;
    font-size: 16px;
    aling: right;
  }

  button span {
    display: flex;
    justify-content: center;
    align-items: center;
    color: #fff;
    font-weight: 600;
  }

  button:hover {
    background-color: #0071e2;
  }

`;

export default DogButton;
