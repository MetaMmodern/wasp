module Wasp.Generator.WebAppGenerator.Setup
  ( installNpmDependencies,
  )
where

import StrongPath (Abs, Dir, Path', (</>))
import Wasp.Generator.Common (ProjectRootDir, oSSpecificNpm)
import qualified Wasp.Generator.Job as J
import Wasp.Generator.Job.Process (runCommandThatRequiresNodeAsJob)
import qualified Wasp.Generator.WebAppGenerator.Common as Common

installNpmDependencies :: Path' Abs (Dir ProjectRootDir) -> J.Job
installNpmDependencies projectDir = do
  let webAppDir = projectDir </> Common.webAppRootDirInProjectRootDir
  runCommandThatRequiresNodeAsJob webAppDir oSSpecificNpm ["install"] J.WebApp
