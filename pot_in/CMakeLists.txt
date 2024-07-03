
# Copyright (c) <current-year> <your-organization>
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

add_vpp_plugin(pot_in
  SOURCES
  pot_in.c
  node.c
  pot_in_periodic.c
  pot_in.h

  MULTIARCH_SOURCES
  node.c

  API_FILES
  pot_in.api

  API_TEST_SOURCES
  pot_in_test.c
)
