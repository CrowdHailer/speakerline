Given('the speaker {string} is in the directory') do |speaker_name|
  @speaker = create(:speaker, name: speaker_name)
end

Given('the speaker {string} is not in the directory') do |name|
  visit speakers_path
  expect(page).not_to have_content(name)
end

When('I add {string} to the directory') do |speaker_name|
  visit new_speaker_path
  page.fill_in 'speaker_name', with: speaker_name
  page.click_on 'Add'
  @speaker = Speaker.find_by(name: speaker_name)
end

When(/^I go to the speaker directory page$/) do
  visit speakers_path
end
