Given('the speaker {string} is not in the directory') do |name|
  visit speakers_path
  expect(page).not_to have_content(name)
end

Given('there is a speaker called {string}') do |name|
  @speaker = create(:speaker, name: name)
end

Given('the speaker {string} is in the directory') do |name|
  create(:speaker, name: name)
end

When(/^I go to the speaker directory page$/) do
  visit speakers_path
end

When(/^I click on 'Sandi Metz'$/) do
  page.click_link('Sandi Metz')
end

When(/^I add 'Katrina Owen' to the directory$/) do
  visit new_speaker_path
  page.fill_in 'speaker_name', with: 'Katrina Owen'
  page.click_on 'Add'
end

Then(/^I should see 'Katrina Owen'$/) do
  expect(page).to have_content('Katrina Owen')
end

Then(/^I should see 'Sandi Metz'$/) do
  expect(page).to have_content('Sandi Metz')
end

Then(/^I should not see 'Lazy Ted'$/) do
  expect(page).not_to have_content('Lazy Ted')
end