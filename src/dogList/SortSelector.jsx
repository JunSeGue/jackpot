import React from "react";
import { Stack, ToggleButton, ToggleButtonGroup } from "@mui/material";

const SortSelector = (props) => {
  const { value, onChange } = props;

  return (
    <Stack direction="row" justifyContent="flex-end" mb={2} padding={'5px'} marginTop={'11px'}>
      <ToggleButtonGroup
        value={value}
        exclusive
        onChange={onChange}
        aria-label="sort options"
      >
        <ToggleButton value="recent">최신순</ToggleButton>
        <ToggleButton value="name">이름순</ToggleButton>
        <ToggleButton value="heart">좋아요순</ToggleButton>
      </ToggleButtonGroup>
    </Stack>
  );
};

export default SortSelector;
